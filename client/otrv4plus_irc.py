# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""The IRC client: `python otrv4+.py`.

The engine it drives (sessions, DAKE, SMP, the TUI widgets) is otrv4+.py,
imported as `otrv4plus`; this is the IRC side -- the connection, nick
handling, commands, and the program's entry point. Split out of otrv4+.py,
which the XMPP client and the apps load as the engine and which carries
none of this any more.

Values the engine changes while it runs (debug flags, the prompt and
scrollback state, Termux detection) are read and written as attributes of
the engine module, `_engine.DEBUG_MODE`, so both sides see one value.
"""
import atexit
import concurrent.futures
import gc
import getpass
import hashlib
import hmac
import json
import os
import re
import resource
import secrets
import shutil
import socket
import struct
import sys
import textwrap
import threading
import time
from typing import Callable, Dict, List, Optional, Set

import otrv4plus as _engine
from otrv4plus import (  # noqa: F401
    EnhancedSessionManager, EventHandler, I2PSAMConnection, IRCConstants,
    MessageRouter, NetworkConstants, OTRConfig, OTRConstants,
    OTRFragmentBuffer, OTRLogger, OTRMessageFragmenter, OTRTracer,
    OTRv4DataMessage, Pager, PanelManager, RUST_DAKE_AVAILABLE,
    RUST_RATCHET_AVAILABLE, SMP_MAX_LEN, SMP_MIN_LEN, Screen, TERMINAL_HEIGHT,
    TERMINAL_WIDTH, TEST_MODE, TIMESTAMP_FORMAT, UIConstants, VERSION,
    _ChannelLogManager, _EOF_SENTINEL, _LOG_AVAILABLE, _display_buffer,
    _emit_line, _flush_display_queue, _handle_input_char, _print_lock,
    _probe_socks5, _read_one_char, _redact_secret, _restore_terminal,
    _safe_b64decode, _sanitise, _scroll_unlock, _secure_file_destroy,
    _secure_wipe, _set_prompt, _setup_raw_mode, _smpflow, _word_wrap,
    advertises_otrv4, colorize, colorize_username, format_names_list,
    otrv4_client_version, safe_print, set_input_mask, socks,
    split_names_entry,
)
from otrv4plus_irc_net import IrcNetMixin
from otrv4plus_irc_pacing import IrcPacingMixin
from otrv4plus_irc_protocol import IrcProtocolMixin
from otrv4plus_irc_ui import IrcUiMixin
from otrv4plus_irc_util import TwentySevenClubNick, _fmt_duration  # noqa: F401 (re-exported)






class OTRv4IRCClient(IrcNetMixin, IrcPacingMixin, IrcProtocolMixin, IrcUiMixin):
    """
    OTRv4 IRC Client - COMPLETE REWRITE
    Fixes:
      * Background recv thread so IRC messages are actually read
      * Connect timeout 120s  (I2P tunnel build takes time)
      * Send timeout 30s
      * Ping watchdog - reconnects after 5 min silence
      * Auto-join
      * No auth / no NickServ (anonymous I2P IRC)
    """

    def __init__(self, config: Optional[OTRConfig] = None):
        self.config = config or OTRConfig()

        self._prompt_refresh_cb: Optional[Callable[[], None]] = None
        self._tui_enabled: bool = False
        self._screen: Optional["Screen"] = None

        self.logger = OTRLogger(self.config)

        self.session_manager = EnhancedSessionManager(self.config, logger=self.logger)
        self.panel_manager = PanelManager(self)
        self.message_router = MessageRouter(self.panel_manager)
        self.event_handler = EventHandler(self.panel_manager)
        # Ephemeral per-channel log: new key per session, files wiped on exit
        self.channel_log = _ChannelLogManager() if _LOG_AVAILABLE else None

        self.server = self.config.server
        if self.config.nickserv_nick:
            self.nick = self.config.nickserv_nick
            # Not the bare nick: the realname is what identifies this client
            # to peers running /names, and a registered nick is no reason to
            # go dark.  See TwentySevenClubNick.real_name.
            self.realname = f"{self .nick } - {VERSION }"
        else:
            self.nick = TwentySevenClubNick.generate()
            self.realname = TwentySevenClubNick.real_name(self.nick)

        #: The nick we want to be using.  A 433 collision may force a
        #: temporary one on us; this is what `_schedule_nick_reclaim` asks
        #: for back once the ghost that took it has timed out.
        self._original_nick = self.nick
        self._nick_reclaim_tries = 0

        self._running_event = threading.Event()
        self._shutdown_event = threading.Event()
        self._connected_event = threading.Event()

        self._reconnecting = False
        self.auto_joined = False
        self.auth_complete = False
        self.nickserv_identified = False
        self.shutting_down = False

        self.sock: Optional[socket.socket] = None
        self._recv_thread: Optional[threading.Thread] = None
        self._recv_buf = ""
        self._sock_lock = threading.Lock()

        self._init_state()

    @property
    def running(self) -> bool:
        return self._running_event.is_set()

    @running.setter
    def running(self, value: bool) -> None:
        self._running_event.set() if value else self._running_event.clear()

    @property
    def connected(self) -> bool:
        return self._connected_event.is_set()

    @connected.setter
    def connected(self, value: bool) -> None:
        self._connected_event.set() if value else self._connected_event.clear()

    @property
    def shutdown_flag(self) -> bool:
        return self._shutdown_event.is_set()

    @shutdown_flag.setter
    def shutdown_flag(self, value: bool) -> None:
        self._shutdown_event.set() if value else self._shutdown_event.clear()

    def _init_state(self) -> None:
        """Complete __init__ attribute setup - called after threading.Event properties."""
        self.last_ping = time.time()
        self.connection_healthy = True
        self.connection_attempts = 0
        self.max_connection_attempts = 999
        self._last_otr_sent: Dict[str, float] = {}

        self.ignored_users: Set[str] = set()
        self.channels: Dict[str, dict] = {}
        self.channel_list: List[dict] = []
        self.whois_data: Dict[str, dict] = {}
        self.names_data: Dict[str, List[str]] = {}
        self._pending_names_pager: Optional[str] = None
        self._who_count: int = 0  # rows printed by current /who
        self._names_limit: int = 500  # max nicks collected per /names
        self.auto_reply_config: Dict[str, dict] = {}

        self.otr_fragmenter = OTRMessageFragmenter()
        self.fragment_buffers: Dict[str, OTRFragmentBuffer] = {}
        self.pager = Pager()

        self.smp_schedule_timers: Dict[str, dict] = {}
        self.auto_smp_monitor_running = False
        self._smp_executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=2, thread_name_prefix="smp_worker"
        )

        self.terminal_width = TERMINAL_WIDTH
        self.terminal_height = TERMINAL_HEIGHT
        self.input_history: List[str] = []
        self.history_index = -1
        self.input_enabled = True
        self.headless = False
        self.test_runner = None

        self.debug_panel_name = "debug" if _engine.DEBUG_MODE else None
        if _engine.DEBUG_MODE:
            self.panel_manager.add_panel("debug", "debug")

        self.tracer = OTRTracer(enabled=_engine.DEBUG_MODE, logger=self.logger)
        self.tracer.set_emit_callback(lambda msg: self._emit("debug", msg))
        self.session_manager.tracer = self.tracer

        def _make_smp_notify(peer: str):
            def _notify(msg: str) -> None:
                try:
                    sec = self.session_manager.get_security_level(peer)
                    self.add_message(peer, msg, sec)
                    self.panel_manager.update_smp_progress(
                        peer, *self.session_manager.get_smp_progress(peer)
                    )

                    self.panel_manager.update_panel_security(peer, sec)
                except Exception:
                    pass

            return _notify

        self.session_manager.smp_notify_factory = _make_smp_notify

        def _ping_refresh() -> None:
            self.last_ping = time.time()

        self.session_manager.ping_refresh_cb = _ping_refresh

        self._emit("debug", "[CLIENT] initialized")

    def debug(self, message: str, data: Optional[dict] = None):
        """Route debug output to the debug panel only - never to raw stdout."""
        if not _engine.DEBUG_MODE:
            return
        msg = message
        if data:
            msg += " | " + json.dumps(data, separators=(",", ":"))
        self._emit("debug", colorize(msg, "magenta"))
        self.logger.debug(message)

    def _emit(self, panel: str, message: str) -> None:
        """
        THE single stdout path - all output flows through here.

        Routing:
          system  → [sys]   always printed
          peer    → [peer]  always printed (private encrypted chat)
          debug   → [debug] printed ONLY when DEBUG_MODE, else buffered silently

        Termux scrollback is the history - we never clear the screen.
        """
        if panel == "debug" and not _engine.DEBUG_MODE:
            return

        if panel not in self.panel_manager.panels:
            ptype = (
                "channel"
                if panel.startswith("#")
                else "debug" if panel == "debug" else "system" if panel == "system" else "private"
            )
            self.panel_manager.add_panel(panel, ptype)

        self.panel_manager.panels[panel].add_message(message)
        if self.panel_manager.active_panel != panel:
            self.panel_manager.panels[panel].unread_count += 1

        _is_background_tab = (
            self.panel_manager.active_panel
            and panel != self.panel_manager.active_panel
            and panel != "system"
            and panel != "debug"
        )
        if _is_background_tab:
            self._termux_notify_message(panel, message)
            if getattr(self, "_tui_enabled", False) and self._screen is not None:
                self._screen.redraw_tabbar()
            return

        ts = colorize(time.strftime(TIMESTAMP_FORMAT), "dark_yellow")
        if panel == "system":
            tag = colorize("[sys]  ", "grey")
        elif panel == "debug":
            tag = colorize("[debug]", "dark_magenta")
        elif panel.startswith("#"):
            tag = colorize(f"[{panel }]", "bold_cyan")
        else:
            _sec = (
                self.session_manager.get_security_level(panel)
                if hasattr(self, "session_manager") and self.session_manager.has_session(panel)
                else None
            )
            _tag_colors = {
                UIConstants.SecurityLevel.ENCRYPTED: "bold_yellow",
                UIConstants.SecurityLevel.FINGERPRINT: "bold_green",
                UIConstants.SecurityLevel.SMP_VERIFIED: "blue",
            }
            _tc = _tag_colors.get(_sec, "green") if _sec is not None else "green"
            tag = colorize(f"[{panel }]", _tc)

        if getattr(self, "_tui_enabled", False) and self._screen is not None:

            self._screen.redraw_body()
        else:
            _emit_line(f"{ts } {tag } {message }")


    def _dispatch_otr_fragment(self, sender: str, fragment: str):
        """Accumulate OTR fragments; process when complete."""
        if sender not in self.fragment_buffers:
            buf = OTRFragmentBuffer(timeout=self.config.fragment_timeout)

            def _on_first_fragment(s: str, n: int, chunk: str = "") -> None:
                """First-fragment UX callback - IRC-aligned.

                Design principles (irssi/weechat convention):
                  • Notices go to the PEER tab only - never cross-posted
                    to the active tab.  Background activity is signalled
                    by tab-bar highlight colour + unread count.
                  • DAKE1 (new session request) gets a visible notice +
                    Termux notification - the user must know someone is
                    knocking.
                  • DAKE2/DAKE3 are mid-handshake - silent.  The peer
                    tab already exists from the DAKE1 that started it.
                  • Encrypted data messages get NO inline "receiving…"
                    notice.  The decrypted text will appear in < 1 s
                    once reassembly completes.  Premature notices just
                    add noise (and we can't distinguish SMP TLVs from
                    normal data at fragment time anyway).
                """
                try:

                    buf.max_fragments_per_sender = UIConstants.FRAGMENT_LIMIT

                    msg_type = None
                    try:
                        import base64 as _b64

                        # Peek only needs the first few decoded bytes to read the
                        # message-type tag.  Use the URL-SAFE alphabet (OTRv4
                        # bodies contain '-'/'_'); a standard b64decode would
                        # drop those chars and could mis-tag the fragment.  Slice
                        # on a 4-char boundary so the truncated body stays valid
                        # base64, then pad.
                        _peek_src = chunk[:16]
                        peek = _b64.urlsafe_b64decode(_peek_src + "=" * (-len(_peek_src) % 4))
                        if (len(peek) >= 3
                                and peek[0] == (OTRv4DataMessage.PROTOCOL_VERSION >> 8)
                                and peek[1] == (OTRv4DataMessage.PROTOCOL_VERSION & 0xFF)):
                            msg_type = "data"
                        elif len(peek) >= 1:
                            msg_type = {
                                0x35: "dake1",
                                0x36: "dake2",
                                0x37: "dake3",
                            }.get(peek[0])
                    except Exception:
                        pass

                    if s not in self.panel_manager.panels:
                        self.panel_manager.add_panel(s, "private")

                    if msg_type == "data" and self.session_manager.has_session(s):
                        buf.max_fragments_per_sender = UIConstants.SMP_FRAGMENT_LIMIT

                    _should_switch = msg_type in (
                        "dake1",
                        "dake2",
                        "dake3",
                    ) or not self.session_manager.has_session(s)
                    if _should_switch:
                        _cur = self.panel_manager.active_panel
                        _cur_panel = self.panel_manager.panels.get(_cur)
                        # Already on the peer's tab -> nothing to switch to.
                        # This used to call _switch_panel anyway, which
                        # replayed the tab's history mid-handshake.
                        _in_channel = (
                            _cur is None
                            or (_cur_panel is not None and _cur_panel.type in ("channel", "system"))
                        )
                        if _in_channel and _cur != s:
                            self._switch_panel(s)

                    if msg_type == "dake1" or not self.session_manager.has_session(s):
                        notice = colorize(
                            f"🔑 {colorize_username (s )} is requesting an OTR session…", "cyan"
                        )
                        self.add_message(s, notice)
                        self._termux_fire(
                            [
                                "--title",
                                "🔑 OTR request",
                                "--content",
                                f"{s } is requesting an encrypted session",
                                "--priority",
                                "high",
                                "--id",
                                f"otrv4_{s }_incoming",
                                "--vibrate",
                                "0,150,100,150",
                            ]
                        )

                except Exception:
                    pass

            buf.first_fragment_cb = _on_first_fragment
            self.fragment_buffers[sender] = buf

        try:
            complete = self.fragment_buffers[sender].add_fragment(sender, fragment)
        except ValueError as exc:
            self.debug("fragment error")
            return
        if complete:
            self.process_otr_payload(sender, complete)

    def process_otr_payload(self, sender: str, payload: str):
        """Route a fully reassembled OTRv4 payload."""
        self.debug("otr payload", {"len": len(payload)})
        try:
            if not payload.startswith("?OTRv4 "):
                return
            raw = payload[7:].strip()
            if not raw:
                return
            decoded = _safe_b64decode(raw)
            if not decoded:
                return
            if (
                OTRv4DataMessage.looks_like_data_frame(decoded)
            ):
                self._handle_data_message(sender, payload)
                return

            msg_type = decoded[0]
            if msg_type == OTRConstants.MESSAGE_TYPE_DAKE1:
                self.process_dake1(sender, payload)
            elif msg_type == OTRConstants.MESSAGE_TYPE_DAKE2:
                self.process_dake2(sender, payload)
            elif msg_type == OTRConstants.MESSAGE_TYPE_DAKE3:
                self.process_dake3(sender, payload)
            elif msg_type == OTRConstants.MESSAGE_TYPE_DATA:
                self._handle_data_message(sender, payload)
        except Exception as exc:
            self.debug(f"otr payload error: {exc }")

    def _handle_data_message(self, sender: str, payload: str):
        """Decrypt an OTRv4 DATA message and route the text to the panel.

        Any valid OTR data message proves the connection is alive, so we reset
        last_ping here to prevent the ping watchdog from firing during a long
        SMP exchange.

        The actual decrypt+SMP computation is offloaded to _smp_executor so the
        recv_loop thread stays free to respond to server PINGs throughout the
        minutes-long 3072-bit DH operations.  Without this, recv_loop blocks
        inside the DH computation, PINGs go unanswered, and the server drops the
        client right after SMP verification succeeds.
        """
        if not self.session_manager.has_session(sender):
            # Was a bare `return`.  Silence here is indistinguishable from the
            # peer having said nothing, and with sessions now surviving a
            # reconnect it is the likeliest way to meet a peer on a new nick.
            self._warn_no_session_for_nick(sender)
            return

        self.last_ping = time.time()

        def _do_decrypt():
            """Run in thread pool - safe because session has its own RLock."""
            try:
                self.last_ping = time.time()

                result = self.session_manager.decrypt_message(sender, payload)
                if result is None:
                    return

                text = (
                    result if isinstance(result, str) else result.decode("utf-8", errors="replace")
                )

                self.last_ping = time.time()

                if text.startswith("?OTRv4 "):
                    self.send_otr_message(sender, text)
                    self.last_ping = time.time()
                    return

                sec = self.session_manager.get_security_level(sender)
                # SECURITY: a decrypted message is peer-controlled content. It is
                # passed through _sanitise() before it reaches the terminal, just
                # like the plaintext path, so a hostile peer cannot hijack the
                # terminal title, reposition the cursor, or inject control codes
                # through an otherwise "trusted" encrypted message.
                _safe_text = _sanitise(text, 512)
                if _safe_text.strip():
                    self.add_message(sender, f"{colorize_username(sender)}: {_safe_text}", sec)
                self.panel_manager.update_panel_security(sender, sec)
                self.panel_manager.update_smp_progress(
                    sender, *self.session_manager.get_smp_progress(sender)
                )

            except Exception as exc:
                self.debug("data decrypt error")

        try:
            self._smp_executor.submit(_do_decrypt)
        except RuntimeError:
            _do_decrypt()

    def _display_plaintext(self, sender: str, target: str, message: str):
        """Show a plaintext PRIVMSG in the right panel.

        Any message whose content looks like OTR wire data - even if it was
        missing the canonical ``?OTRv4 `` prefix - is routed to the OTR
        dispatcher and silently dropped rather than shown as a chat message.
        This prevents protocol artefacts like ``otrv4_smp:<base64>`` from
        appearing as chat lines attributed to a nick.
        """
        _OTR_PROTO_MARKERS = ("?OTRv4", "?OTR", "otrv4_smp", "otrv4:")
        if any(message.startswith(m) for m in _OTR_PROTO_MARKERS):
            self._dispatch_otr_fragment(sender, message)
            return
        if message.startswith("\x01ACTION ") and message.endswith("\x01"):
            panel = target if target.startswith("#") else sender
            self.add_message(
                panel, colorize(f"* {sender } {_sanitise (message [8 :-1 ],490 )}", "cyan")
            )
            return
        panel = target if target.startswith("#") else sender
        _safe_msg = _sanitise(message, 512)
        self.add_message(
            panel,
            colorize_username(sender) + colorize(":", "dim") + f" {colorize (_safe_msg ,'white')}",
        )

        if not target.startswith("#"):
            _active = self.panel_manager.active_panel
            if _active and _active != panel and _active not in ("system", "debug"):
                _hint = colorize(
                    f"\U0001f4ac PM from {sender } - /switch {sender } to view", "yellow"
                )
                self._emit(_active, _hint)

    def process_dake1(self, sender: str, payload: str):
        active = self.panel_manager.active_panel
        alert = colorize(
            f"🔑 OTR request from {_sanitise (sender ,64 )} - switching to their tab…", "cyan"
        )
        if active:
            self.add_message(active, alert)
        else:
            self.add_message("system", alert)
        self._route_otr_to_session_manager(sender, payload, "DAKE1", is_initiator=False)

    def process_dake2(self, sender: str, payload: str):
        pass

    def process_dake3(self, sender: str, payload: str):
        pass

    def process_smp_message(self, sender: str, data: bytes):
        pass

    def auto_join_channel(self):
        """Join channels after RPL_WELCOME.

        On first connect: joins the default channel.
        On reconnect: rejoins all channels the user was in before disconnect.
        """
        if not self.auto_joined and self.connected:
            rejoin = getattr(self, "_rejoin_channels", [])
            if rejoin:
                channels_to_join = rejoin
                self._rejoin_channels = []
            else:
                channels_to_join = [self.config.channel]

            seen = set()
            ordered = []
            for ch in channels_to_join:
                if ch.lower() not in seen:
                    seen.add(ch.lower())
                    ordered.append(ch)
            if self.config.channel.lower() not in seen:
                ordered.insert(0, self.config.channel)

            for ch in ordered:
                self.send(f"JOIN {ch }")
                self.add_message("system", f"Auto-joining {colorize (ch ,'cyan')}…")
                self.debug("auto_join", {"channel": ch})

            self.auto_joined = True
            self.connection_attempts = 0
            # After the rejoin, not before: the user should see what survived
            # once there is somewhere to say it.
            try:
                self._report_preserved_sessions()
            except Exception:
                self.debug("could not report preserved sessions")

            # Only peers whose session did NOT survive.  This used to list
            # every peer panel that had any history, which was correct while
            # _try_reconnect cleared the sessions and became a flat
            # contradiction when v10.24.0 stopped: a handset printed
            #
            #   🔐 1 OTR session(s) kept through the reconnect — identity keys
            #      and pinned fingerprints unchanged.
            #   ⚠ OTR sessions lost on reconnect - /otr IvoryDelta
            #
            # two lines apart, about the same session.  Of the two the second
            # was the wrong one, and it is the one that tells the user to
            # throw away a working session and spend four minutes rebuilding
            # it.
            try:
                peers = [
                    name
                    for name, p in self.panel_manager.panels.items()
                    if not name.startswith("#")
                    and name not in ("system", "debug")
                    and p.history
                    and not self.session_manager.has_session(name)
                ]
            except Exception:
                # Fail quiet rather than fail loud: a wrong "sessions lost"
                # costs the user a rebuild, a missing one costs a message.
                peers = []
            if peers:
                self.add_message(
                    "system",
                    colorize(
                        "⚠ No OTR session with "
                        + ", ".join(f"{p }" for p in peers)
                        + " after the reconnect - "
                        + ", ".join(f"/otr {p }" for p in peers),
                        "yellow",
                    ),
                )

    def start_auto_smp_monitor(self):
        """Background thread that fires scheduled SMP verifications."""
        if self.auto_smp_monitor_running:
            return
        self.auto_smp_monitor_running = True

        def _monitor():
            while self.running and not self.shutdown_flag:
                now = time.time()
                due = [
                    peer
                    for peer, info in list(self.smp_schedule_timers.items())
                    if info.get("scheduled") and now >= info.get("when", 0)
                ]
                for peer in due:
                    del self.smp_schedule_timers[peer]
                    try:
                        self._fire_auto_smp(peer)
                    except Exception as exc:
                        self.debug("auto_smp error")
                time.sleep(1)

        threading.Thread(target=_monitor, daemon=True, name="smp-monitor").start()

    def _fire_auto_smp(self, peer: str):
        """Attempt to start SMP with the stored secret for peer."""
        start = getattr(self.session_manager, "start_smp_with_stored_secret", None)
        if start is None:
            return
        tlv = start(peer)
        if tlv:
            enc = self.session_manager.encrypt_message(peer, "")
            if enc:
                self.send_otr_message(peer, enc)

    def schedule_auto_smp(self, peer: str, delay: float = 2.0):
        if peer not in self.smp_schedule_timers:
            self.smp_schedule_timers[peer] = {"when": time.time() + delay, "scheduled": True}

    def clear_pending_smp(self, peer: str):
        self.smp_schedule_timers.pop(peer, None)

    def add_message(
        self,
        target: str,
        message: str,
        security_level: Optional[UIConstants.SecurityLevel] = None,
        is_initiator: Optional[bool] = None,
    ):
        """
        Route a message to the correct panel and emit to stdout.

        Panel routing:
          'system'  → system tab (server welcome, MOTD, connection events)
          '#channel'→ channel tab (join/part/quit/channel chat)
          'debug'   → debug tab only (never shown in other tabs)
          peer_nick → private/secure tab (encrypted messages after DAKE)
        """
        if target in self.ignored_users:
            return
        if security_level is None:
            if not target.startswith("#"):
                if self.session_manager.has_session(target):
                    security_level = self.session_manager.get_security_level(target)
                elif target in self.panel_manager.panels:
                    security_level = self.panel_manager.panels[target].security_level
        icon = UIConstants.SECURITY_ICONS.get(security_level, "") if security_level else ""
        if icon and not message.startswith(icon):
            message = f"{icon }{message }"
        self._emit(target, message)
        if security_level is not None:
            self.panel_manager.update_panel_security(target, security_level)

    _CTCP_BLOCKED = frozenset(
        {
            "VERSION",
            "FINGER",
            "USERINFO",
            "CLIENTINFO",
            "DCC",
            "PING",
            "TIME",
            "SOURCE",
        }
    )

    def is_ctcp_message(self, message: str) -> bool:
        if message.startswith("?OTRv4"):
            return False
        if message.startswith("\x01") and message.endswith("\x01"):
            cmd = message[1:-1].split()[0].upper() if message[1:-1].split() else ""
            if cmd == "ACTION":
                return False
            return True
        return False

    def check_auto_reply(self, sender: str, target: str, message: str):
        if sender == self.nick or sender not in self.auto_reply_config:
            return
        cfg = self.auto_reply_config[sender]
        if "channels" in cfg and cfg["channels"] and target not in cfg["channels"]:
            return
        reply = cfg.get("message", "")
        if reply:
            dest = sender if target == self.nick else target

            def _send_reply(d=dest, r=reply):
                self.send(f"PRIVMSG {d } :{r }")
                self.add_message(d, f"{colorize_username (self .nick )}: {r }")

            threading.Timer(0.3, _send_reply).start()

    def start_guided_otr_session(self, nick: str):
        """Kick off a DAKE handshake with nick."""
        if nick not in self.panel_manager.panels:
            self.panel_manager.add_panel(nick, "private")
        self._switch_panel(nick)
        self.add_message(
            nick, colorize(f"🔑 Initiating OTR with {colorize_username (nick )}…", "cyan")
        )
        dake_msg, should_send = self.session_manager.handle_outgoing_message(nick, "")
        if dake_msg and should_send:
            self.send_otr_message(nick, dake_msg)
            self.add_message(
                nick, colorize(f"🔑 DAKE1 → sent - waiting for response…", "bold_cyan")
            )

    def shutdown(self):
        self.add_message("system", colorize("🛑 Shutting down…", "yellow"))
        self.running = False
        self.shutdown_flag = True
        try:
            if self.sock:
                self.send_raw("QUIT :OTRv4 client shutting down")
                import ssl as _ssl

                if isinstance(self.sock, _ssl.SSLSocket):
                    try:
                        self.sock.unwrap()  # TLS close-notify
                    except Exception:
                        pass
                self.sock.close()
        except Exception:
            pass
        self.sock = None

        try:
            if hasattr(self, "_sam_connection") and self._sam_connection:
                self._sam_connection.close()
                self._sam_connection = None
        except Exception:
            pass
        try:
            self._smp_executor.shutdown(wait=False, cancel_futures=True)
        except TypeError:
            self._smp_executor.shutdown(wait=False)
        except Exception:
            pass

        # Last thing before the process goes: the conversation must not be
        # left in the terminal for whoever picks the handset up next, and it
        # must not be sitting in the heap for whatever reads a core dump.
        # announce=False -- there is no panel left worth writing to.
        try:
            self._purge_scrollback("shutdown", announce=False)
        except Exception:
            pass

        safe_print(colorize("✅ Clean shutdown complete", "green"))

    def send_privmsg(self, target: str, message: str) -> bool:
        return self.send(f"PRIVMSG {target } :{message }")


class EnhancedOTRv4IRCClient(OTRv4IRCClient):
    """
    Full OTRv4 IRC client with:
      - Complete DAKE handshake (DAKE1/2/3)      🦀 Rust
      - Double ratchet encryption                  🦀 Rust
      - SMP verification with auto-respond         🦀 Rust
      - Fingerprint trust database
      - Traffic-light security indicator (🔴🟡🟢🔵)
      - All prompts IN-CHAT (no blocking input() calls)
      - remote fingerprint display and auto-switch to private panel
      - manual SMP start only
      - SMP start works with encrypted messages
    """

    def __init__(self, config=None):
        super().__init__(config)

        self._pending_action: Optional[dict] = None
        self._pending_lock = threading.Lock()

        # v10.23.0: the guided SMP flow the XMPP client has had since
        # v10.15.  The registry decides which question the user is being
        # asked and, crucially, whether the answer may be a passphrase.
        self._smp_flows = _smpflow.SmpFlowRegistry()
        #: Peer whose passphrase we are reading right now, or None.  Set ONLY
        #: from a local path -- a bare /smp, or a local `y` answering a
        #: consent prompt.  Nothing a peer sends may set it (INV-06).
        self._secret_request: Optional[str] = None
        #: "start" (we go first) or "resume" (answer the SMP1 already held).
        self._secret_purpose: Optional[str] = None
        #: Peer whose consent prompt is on screen, so a resent SMP1 cannot
        #: print it twice.
        self._smp_consent_shown: Optional[str] = None

        # Tell the engine to PARK an inbound SMP1 when no passphrase is set,
        # rather than aborting it.  Without this the responder's SMP1 dies
        # before the user can be asked, and answering means a second round
        # trip over I2P.  The XMPP client sets the same flag.
        try:
            self.session_manager.smp_guided_prompt = True
        except Exception:
            pass

    def _set_pending(self, action_type: str, peer: str, **kwargs):
        """Register a pending action waiting for user input in chat."""
        with self._pending_lock:
            self._pending_action = {"type": action_type, "peer": peer, **kwargs}

    def _clear_pending(self):
        with self._pending_lock:
            self._pending_action = None

    def _get_pending(self) -> Optional[dict]:
        with self._pending_lock:
            return self._pending_action

    def _dispatch_pending_response(self, text: str) -> bool:
        """
        Called from handle_chat_message when a pending action exists.
        Returns True if the input was consumed by a pending action.
        """
        action = self._get_pending()
        if not action:
            return False

        atype = action["type"]
        peer = action["peer"]
        self._clear_pending()

        if atype == "trust":
            self._handle_trust_response(peer, text.strip().lower(), action)
            return True

        if atype == "smp_consent":
            # A REMOTE SMP1 armed this prompt, and that is allowed: it asks a
            # y/n question and consumes one keystroke's worth of answer. What
            # it must never do is consume the line as a passphrase -- only
            # `y` reaches `_arm_secret_prompt`, and an ordinary message here
            # is refused rather than swallowed.
            answer = text.strip().lower()
            if answer in ("y", "yes", "n", "no"):
                self._handle_smp_consent(peer, answer)
                return True
            # Not an answer. Re-arm the question and let the line through as
            # the ordinary message it is.
            self._set_pending("smp_consent", peer)
            return False

        # There is deliberately no "smp_secret" branch.  It existed, it was
        # armed from a remote-reachable path, and it turned the user's next
        # line into a shared secret.  Removing the branch as well as the
        # arming means reintroducing the defect takes two edits rather than
        # one, and tests/test_no_remote_input_capture.py fails on either.
        return False

    def process_dake1(self, sender: str, payload: str):
        """DAKE1 reassembled - process as responder.

        _on_first_fragment already created the peer tab and switched to it
        on fragment 1.  By the time we arrive here all fragments are in.
        """
        if sender not in self.panel_manager.panels:
            self.panel_manager.add_panel(sender, "secure")
        if self.panel_manager.active_panel != sender:
            self._switch_panel(sender)
        # Stage 1 for the responder is "their request arrived and parsed".
        # _route_otr_to_session_manager reports stage 2 when it sends the
        # answer, so the verdict for each stage comes from the code that
        # performed it.
        self._dake_stage(sender, 1, "ok", note="their request — answering")
        self._route_otr_to_session_manager(sender, payload, "DAKE1", is_initiator=False)

    def process_dake2(self, sender: str, payload: str):
        """DAKE2 received → send DAKE3 → session ENCRYPTED (initiator)."""
        if sender not in self.panel_manager.panels:
            self.panel_manager.add_panel(sender, "private")
        self._route_otr_to_session_manager(sender, payload, "DAKE2", is_initiator=True)
        sec = self.session_manager.get_security_level(sender)
        if sec == UIConstants.SecurityLevel.ENCRYPTED:
            # Both verdicts are reported here, after the fact: routing DAKE2
            # is what produces DAKE3, so neither is OK until this returned an
            # encrypted session.
            self._dake_stage(sender, 2, "ok")
            self._dake_stage(sender, 3, "ok",
                             detail="sent — %d fragments"
                                    % getattr(self, "_last_fragment_count", 0))
            self._handle_session_established(sender, is_initiator=True)
        else:
            self._dake_stage(sender, 2, "processed, but the session is not "
                                        "encrypted")

    def process_dake3(self, sender: str, payload: str):
        """DAKE3 received → session ENCRYPTED (responder)."""
        if sender not in self.panel_manager.panels:
            self.panel_manager.add_panel(sender, "secure")
        self._route_otr_to_session_manager(sender, payload, "DAKE3", is_initiator=False)
        sec = self.session_manager.get_security_level(sender)
        if sec == UIConstants.SecurityLevel.ENCRYPTED:
            self._dake_stage(sender, 3, "ok")
            self._handle_session_established(sender, is_initiator=False)
        else:
            self._dake_stage(sender, 3, "processed, but the session is not "
                                        "encrypted")

    def _route_otr_to_session_manager(
        self, sender: str, payload: str, label: str, is_initiator: bool
    ):
        """Feed a raw OTRv4 payload to the session manager and handle the response.

        KNOWN HAZARD, not fixed here.  This runs on the receive thread --
        `_recv_loop` calls `handle_message` directly -- and the answer it
        sends is a multi-fragment message.  A responder's DAKE2 is 24
        fragments, which at the default pacing is about 72 seconds during
        which the receive thread is inside `time.sleep()` and therefore
        cannot read the socket or answer a server PING.  Most ircds ping
        every 120s and kill after another 120s, so one send does not do it,
        but they stack.

        The same disease was fixed for the SMP path -- `_handle_data_message`
        offloads to `_smp_executor` with a comment saying exactly this -- and
        the DAKE path never was.

        It is left alone deliberately for now.  Fixing it means sending on a
        worker, which means the stage report ("DAKE 2 / OK") has to move to a
        completion callback so it still fires only after the send succeeded,
        and that is a restructure of the handshake display on the same day it
        first worked end to end.  The disconnect this was investigated for
        happened on the INITIATOR, whose sends run on the main thread and
        whose receive thread was not blocked, so this is not the cause of it.
        `_report_disconnect_context` prints seconds-since-last-server-message
        precisely so the next occurrence says whether it is.
        """
        try:
            result = self.session_manager.handle_incoming_message(sender, payload)
            if result and isinstance(result, (bytes, str)):
                resp = (
                    result if isinstance(result, str) else result.decode("utf-8", errors="replace")
                )
                if resp.startswith("?OTRv4 "):
                    sent = self.send_otr_message(sender, resp)
                    if label == "DAKE1":
                        if sender not in self.panel_manager.panels:
                            self.panel_manager.add_panel(sender, "secure")
                        self._dake_stage(
                            sender, 2, "ok" if sent else "could not send the "
                                                        "answer",
                            detail="sent — %d fragments"
                                   % getattr(self, "_last_fragment_count", 0))
                    return
            self.debug(f"{label } processed")
        except Exception as exc:
            self.debug("operation error")
            # Against the stage it happened in, in the peer's own tab, rather
            # than as an undifferentiated error in the system tab.  The
            # message is the exception's class and a sanitised prefix -- a
            # handshake failure reason must not carry transcript bytes.
            stage = {"DAKE1": 1, "DAKE2": 2, "DAKE3": 3}.get(label)
            if stage is not None:
                self._dake_stage(sender, stage,
                                 "%s: %s" % (type(exc).__name__,
                                             _sanitise(str(exc), 60)))
            else:
                self.add_message(
                    "system",
                    f"{colorize (f'❌ {label } error from','red')} {sender }: "
                    f"{_sanitise (str (exc ),60 )}",
                )

    def _clear_no_session_warning(self, peer: str) -> None:
        """Forget that we warned about *peer*, now that a session exists.

        Without this the warning is once per process: a peer who starts a
        session, loses it and sends again would be dropped silently the second
        time, which is the behaviour this replaced.
        """
        warned = getattr(self, "_no_session_warned", None)
        if warned is not None:
            warned.discard(peer)

    def _otr_panel(self, peer: str) -> str:
        """Return the panel name for OTR private conversation (always the peer's private panel)."""
        if peer not in self.panel_manager.panels:
            self.panel_manager.add_panel(peer, "secure")
        return peer

    def _handle_session_established(self, peer: str, is_initiator: bool):
        """Called after DAKE completes. Shows fingerprints and trust prompt in PRIVATE panel."""
        try:
            channel_panel = None
            for ch, info in self.channels.items():
                if peer in info.get("users", set()):
                    channel_panel = ch
                    break

            if peer not in self.panel_manager.panels:
                self.panel_manager.add_panel(peer, "secure")

            sec = UIConstants.SecurityLevel.ENCRYPTED
            self.panel_manager.update_panel_security(peer, sec)
            if channel_panel:
                self.panel_manager.update_panel_security(channel_panel, sec)

            role = "initiator" if is_initiator else "responder"

            _session = (
                self.session_manager.get_session(peer)
                if hasattr(self.session_manager, "get_session")
                else None
            )
            _backend = getattr(_session, "_ratchet_backend", "python") if _session else "python"
            _ratchet_tag = "🦀 Rust" if _backend == "rust" else "🐍 Python"
            _dake_engine = getattr(_session, "dake_engine", None)
            _dake_tag = "🦀 Rust"
            _smp_tag = (
                "🦀 Rust" if (getattr(_session, "rust_smp", None) is not None) else "🐍 Python"
            )

            if channel_panel:
                self.add_message(
                    channel_panel,
                    f"🔒 OTR session with {colorize_username (peer )} established"
                    f" - Ed448/X448, AES-256-GCM ({role })"
                    f" [DAKE {_dake_tag } | Ratchet {_ratchet_tag } | SMP {_smp_tag }]",
                    sec,
                )

            local_fp = self._get_local_fp()
            remote_fp = self._get_remote_fp(peer)

            self.add_message(peer, colorize("─" * 50, "dim"), sec)
            self.add_message(peer, colorize(f"🔑 FINGERPRINTS ({peer })", "cyan"), sec)
            self.add_message(peer, f"  Yours : {colorize (self ._fmt_fp (local_fp ),'green')}", sec)
            self.add_message(
                peer, f"  Theirs: {colorize (self ._fmt_fp (remote_fp ),'yellow')}", sec
            )
            self.add_message(peer, colorize("─" * 50, "dim"), sec)

            if self.panel_manager.active_panel != peer:
                self._switch_panel(peer)
            else:
                if self._prompt_refresh_cb is not None:
                    self._prompt_refresh_cb()

            already_trusted = False
            if remote_fp:
                try:
                    if hasattr(self.session_manager, "is_peer_trusted"):
                        already_trusted = self.session_manager.is_peer_trusted(peer)
                    elif hasattr(self.session_manager, "trust_db"):
                        already_trusted = self.session_manager.trust_db.is_trusted(peer, remote_fp)
                except Exception:
                    already_trusted = False

            # v10.23.0: TOFU, matching the XMPP client.  A y/n prompt here
            # asked the user to make a decision they had no way to make --
            # nobody compares a 57-byte fingerprint against nothing on first
            # contact -- and it was armed by a remote DAKE, which is the
            # shape INV-06 exists to keep out of the client.  First contact
            # now pins silently; a CHANGE is reported and never auto-accepted.
            #
            # Nothing is written to disk: INV-10 says an IRC run persists no
            # trust state, and TrustDatabase._save already returns early when
            # not persistent.  This pin lives for the session, which is what
            # an ephemeral IRC identity should have.
            if already_trusted:
                self.add_message(peer, colorize("✅ Fingerprint already trusted", "green"), sec)
                self._finish_trust(
                    peer, trusted=True, remote_fp=remote_fp, is_initiator=is_initiator
                )
            elif self._fingerprint_changed(peer, remote_fp):
                # The one case that must stop and ask.  A different key for a
                # nick we have seen before is either a new person on that nick
                # -- routine on IRC -- or someone in the middle, and the
                # client cannot tell which.  Never auto-accept it (INV-11).
                self.add_message(peer, colorize(
                    "⚠️  FINGERPRINT CHANGED for this nick. This is either a "
                    "different person using the nick, or someone in the "
                    "middle.", "red"), sec)
                self.add_message(peer, colorize(
                    "Encrypted, but NOT verified. Use  /trust-reset " + peer +
                    "  if you are sure, then verify with  /smp.", "yellow"), sec)
                self._finish_trust(
                    peer, trusted=False, remote_fp=remote_fp,
                    is_initiator=is_initiator
                )
            else:
                self.add_message(peer, colorize(
                    "🔑 First contact — fingerprint pinned for this nick.",
                    "cyan"), sec)
                self.add_message(peer, colorize(
                    "A change will be reported. Pinning is not verification: "
                    "run  /smp  to prove who they are.", "dim"), sec)
                try:
                    if hasattr(self.session_manager, "trust_fingerprint"):
                        self.session_manager.trust_fingerprint(peer, remote_fp)
                except Exception:
                    self.debug("first-contact pin failed")
                self._finish_trust(
                    peer, trusted=True, remote_fp=remote_fp, is_initiator=is_initiator
                )

        except Exception as exc:
            self.debug("_handle_session_established error")
            self.add_message(
                "system", f"{colorize ('❌ Session setup error:','red')} {str (exc )[:100 ]}"
            )

    def _fingerprint_changed(self, peer: str, remote_fp: str) -> bool:
        """True if we have a DIFFERENT fingerprint stored for this nick.

        First contact (nothing stored) is not a change; that is the case
        TOFU pins silently. Compared with `hmac.compare_digest` rather than
        `!=` for the same reason the trust database does: a fingerprint
        comparison is a security decision and should not leak its result
        through timing, cheap as that leak is here.
        """
        if not remote_fp:
            return False
        try:
            db = getattr(self.session_manager, "trust_db", None)
            if db is None:
                return False
            entry = db._db.get(peer)
            if not entry:
                return False
            stored = entry.get("fingerprint", "")
            if not stored:
                return False
            return not hmac.compare_digest(stored.encode("utf-8"),
                                           remote_fp.encode("utf-8"))
        except Exception:
            # Cannot tell -> treat as unchanged rather than crying wolf on
            # every session. The pin below is a no-op if one already exists.
            return False

    # -- the guided SMP flow, shared with the XMPP client -----------------
    #
    # The rule, and the whole reason this goes through SmpFlow rather than
    # the old _set_pending("smp_secret"): a remote message may move the local
    # state to AWAITING_LOCAL_CONSENT and no further. Only local input --
    # a bare /smp, or a `y` the user pressed -- reaches AWAITING_SECRET,
    # which is the state in which the next line is read as a passphrase.
    # SmpFlow has no edge that skips the consent step (INV-06).

    def _arm_secret_prompt(self, peer: str, purpose: str) -> None:
        """Arm the hidden read. `purpose` is "start" or "resume"."""
        self._secret_request = peer
        self._secret_purpose = purpose
        set_input_mask(True)
        sec = self._panel_sec(peer)
        self.add_message(peer, colorize(
            "🔐 Passphrase (hidden), or Enter to cancel:", "cyan"), sec)
        if self._prompt_refresh_cb is not None:
            try:
                self._prompt_refresh_cb()
            except Exception:
                pass

    def _disarm_secret_prompt(self) -> None:
        """Stop reading a passphrase, whatever the outcome.

        Always paired with arming, including on every error path: leaving the
        mask on would hide the user's ordinary chat, and leaving
        `_secret_request` set would make their next line a passphrase.
        """
        self._secret_request = None
        self._secret_purpose = None
        set_input_mask(False)
        if self._prompt_refresh_cb is not None:
            try:
                self._prompt_refresh_cb()
            except Exception:
                pass

    def _panel_sec(self, peer: str):
        try:
            return self.session_manager.get_security_level(peer)
        except Exception:
            return UIConstants.SecurityLevel.ENCRYPTED

    def _consume_secret_line(self, text: str) -> bool:
        """Take one line as the passphrase, if one was asked for locally.

        Returns True if the line was consumed. `_secret_request` is set only
        by `_smp_verify` (a typed /smp) and `_handle_smp_consent` (a typed
        y) -- never by anything a peer sends.
        """
        peer = self._secret_request
        if peer is None:
            return False
        purpose = self._secret_purpose
        self._disarm_secret_prompt()
        flow = self._smp_flows.get(peer)

        secret = text  # NOT stripped: leading/trailing spaces are the user's
        if not secret:
            try:
                flow.secret_cancelled()
            except _smpflow.SmpFlowError:
                pass
            self.add_message(peer, colorize(
                "🔐 Cancelled — nothing was stored or sent.", "yellow"),
                self._panel_sec(peer))
            if purpose == "resume":
                self._decline_smp_request(peer, "declined")
            return True

        if not (SMP_MIN_LEN <= len(secret) <= SMP_MAX_LEN):
            try:
                flow.secret_cancelled()
            except _smpflow.SmpFlowError:
                pass
            # The LENGTH is named, never the value.
            self.add_message(peer, colorize(
                "🔐 Passphrase must be %d-%d characters. Nothing stored; "
                "run /smp again." % (SMP_MIN_LEN, SMP_MAX_LEN), "yellow"),
                self._panel_sec(peer))
            return True

        try:
            # set_smp_secret, NOT smp_storage.set_secret.  The storage call
            # writes the file and stops there; only this one also binds the
            # passphrase into the session's Rust SMP engine.  The responder
            # path needs the engine copy: resume_held_smp1_generate_smp2()
            # fails closed with "secret still not set: cannot answer the held
            # SMP1" when the engine has nothing, which surfaced on a handset
            # as "Could not answer the held request: ValueError" immediately
            # after the passphrase was accepted.  The initiator path did not
            # show it because _start_smp binds the secret itself on the way
            # past; that asymmetry was the whole defect.  The XMPP client has
            # always called set_smp_secret here.
            #
            # Binding twice (here and again in _start_smp on the initiator
            # path) is deliberate and safe: session.set_smp_secret permits a
            # rebind in IDLE and in SECRET_REQUIRED, and rebinding the same
            # passphrase is idempotent.  It costs one extra SHAKE-256 stretch
            # rather than an asymmetry between the two paths.
            if hasattr(self.session_manager, "set_smp_secret"):
                self.session_manager.set_smp_secret(peer, secret)
            else:
                self.session_manager.smp_storage.set_secret(peer, secret)
            flow.secret_supplied()
        except Exception as exc:
            # The passphrase is in scope here, so the reason is redacted
            # before it is shown.  _redact_secret is belt-and-braces: no
            # exception on this path is known to quote its argument, and the
            # test that proves it uses a raiser that deliberately does.
            self.add_message(peer, colorize(
                "🔐 Could not store the passphrase: %s"
                % _redact_secret(type(exc).__name__, secret), "red"),
                self._panel_sec(peer))
            try:
                flow.reset()
            except _smpflow.SmpFlowError:
                pass
            return True
        finally:
            # The local copy goes now. It is a Python str so this drops the
            # reference rather than wiping the characters -- the engine has
            # already copied it into Rust-owned zeroizing memory, which is
            # the copy that matters (INV-02 records the same limit).
            secret = None

        self.add_message(peer, colorize(
            "🔐 Passphrase stored — verifying…", "cyan"), self._panel_sec(peer))
        if purpose == "resume":
            self._resume_smp(peer)
        else:
            try:
                flow.running()
            except _smpflow.SmpFlowError:
                pass
            self._start_smp(peer, None)      # the passphrase just stored
        return True

    def _smp_verify(self, peer: str) -> None:
        """Bare `/smp` — verify, asking for whatever is missing.

        Replaces "type /smp <passphrase> (it will be visible on this
        terminal)", which asked the user to put a shared secret into their
        scrollback. `_finish_trust` had been promising this prompt existed
        since v10.15; on this client it did not.
        """
        flow = self._smp_flows.get(peer)
        if flow.state in (_smpflow.AWAITING_LOCAL_CONSENT,
                          _smpflow.AWAITING_SECRET):
            self.add_message(peer, colorize(
                "🔐 Already asking you for the passphrase — answer that "
                "prompt.", "yellow"), self._panel_sec(peer))
            return

        stored = False
        try:
            stored = self.session_manager.has_stored_smp_secret(peer)
        except Exception:
            stored = False
        if stored:
            self.add_message(peer, colorize(
                "🔐 Stored passphrase found for %s — verifying…" % peer,
                "cyan"), self._panel_sec(peer))
            try:
                flow.running()
            except _smpflow.SmpFlowError:
                pass
            self._start_smp(peer, None)
            return

        try:
            flow.local_secret_needed()
        except _smpflow.SmpFlowError as e:
            self.add_message(peer, colorize("🔐 %s" % e, "yellow"),
                             self._panel_sec(peer))
            return
        sec = self._panel_sec(peer)
        self.add_message(peer, colorize(
            "🔐 Verification needs the passphrase you agreed with this "
            "contact, out of band.", "cyan"), sec)
        self.add_message(peer, colorize(
            "🔐 Both sides must enter the SAME text (%d-%d characters)."
            % (SMP_MIN_LEN, SMP_MAX_LEN), "dim"), sec)
        self._arm_secret_prompt(peer, purpose="start")

    def _announce_secret_required(self, peer: str) -> None:
        """A peer asked to verify and we hold no passphrase for them.

        Prints and moves to AWAITING_LOCAL_CONSENT. It arms NOTHING that
        could consume a line as a secret: if the user types an ordinary
        message here it is sent as an ordinary message.
        """
        flow = self._smp_flows.get(peer)
        try:
            state = flow.remote_smp1_arrived()
        except _smpflow.SmpFlowError:
            return
        if state != _smpflow.AWAITING_LOCAL_CONSENT:
            return
        if self._smp_consent_shown == peer:
            return          # a resent SMP1 must not print a second prompt
        self._smp_consent_shown = peer
        sec = self._panel_sec(peer)
        self.add_message(peer, colorize("─" * 50, "dim"), sec)
        self.add_message(peer, colorize(
            "🔐 SMP VERIFICATION REQUEST", "blue"), sec)
        self.add_message(peer, colorize(
            "%s wants to verify this session using a passphrase you agreed "
            "in advance." % _sanitise(peer, 64), "cyan"), sec)
        self.add_message(peer, colorize(
            "Press  y  to enter that passphrase, or  n  to decline.",
            "yellow"), sec)
        self.add_message(peer, colorize(
            "Nothing you type now is sent to them, and an ordinary message "
            "here is just an ordinary message.", "dim"), sec)
        self.add_message(peer, colorize("─" * 50, "dim"), sec)
        self._set_pending("smp_consent", peer)

    def _handle_smp_consent(self, peer: str, answer: str) -> None:
        """The local y/n. The only door into the passphrase prompt for a
        request a peer made."""
        flow = self._smp_flows.get(peer)
        agreed = answer.strip().lower() in ("y", "yes")
        try:
            flow.local_consent(agreed)
        except _smpflow.SmpFlowError as e:
            self.add_message(peer, colorize("🔐 %s" % e, "yellow"),
                             self._panel_sec(peer))
            return
        self._smp_consent_shown = None
        if not agreed:
            self._decline_smp_request(peer, "declined")
            return
        self.add_message(peer, colorize(
            "🔐 Enter the passphrase you agreed with this contact.", "cyan"),
            self._panel_sec(peer))
        self._arm_secret_prompt(peer, purpose="resume")

    def _decline_smp_request(self, peer: str, why: str) -> None:
        """Tell the peer, drop the held SMP1, keep nothing."""
        flow = self._smp_flows.get(peer)
        try:
            flow.reset()
        except _smpflow.SmpFlowError:
            pass
        self._smp_consent_shown = None
        abort = None
        try:
            abort = self.session_manager.decline_held_smp1(peer)
        except Exception:
            self.debug("decline_held_smp1 failed")
        if abort:
            try:
                self.send_otr_message(peer, abort)
            except Exception:
                self.debug("could not send SMP abort")
        self.add_message(peer, colorize(
            "🔐 Verification declined." if why == "declined"
            else "🔐 Verification request expired.", "yellow"),
            self._panel_sec(peer))

    def _resume_smp(self, peer: str) -> None:
        """Answer the SMP1 the engine parked, without a second round trip.

        Called once, from the hidden read, after the user consented.  The
        held message is the engine's to consume: this asks for the SMP2 and
        sends it, and does not itself decide whether the passphrase matched
        -- that is four messages away.

        The failure report names the engine's reason.  It used to print only
        `type(exc).__name__`, which turned "secret still not set: cannot
        answer the held SMP1" into the word "ValueError" and cost a
        two-handset session to diagnose.  Every string the engine raises on
        this path is a fixed literal in Rust/src/smp.rs; the passphrase is
        not an argument to any call made here, so there is nothing of the
        user's in it.  It is sanitised and length-capped regardless, because
        "there is nothing sensitive in this string" is a claim that rots.
        """
        flow = self._smp_flows.get(peer)
        if not flow.has_held_smp1:
            # A second `y`, or a resume after the request was declined or
            # expired.  The engine would refuse anyway; saying so here keeps
            # the reason accurate rather than reporting an engine error for
            # something the front end already knew.
            self.add_message(peer, colorize(
                "🔐 There is no verification request waiting — ask them to "
                "run /smp again.", "yellow"), self._panel_sec(peer))
            return
        try:
            smp2 = self.session_manager.resume_held_smp1(peer)
        except Exception as exc:
            self.add_message(peer, colorize(
                "🔐 Could not answer the held request: %s"
                % _sanitise(str(exc), 160), "red"), self._panel_sec(peer))
            self.add_message(peer, colorize(
                "🔐 Nothing was sent and nothing is verified. Run  /smp  to "
                "try again.", "yellow"), self._panel_sec(peer))
            # Back to IDLE, not FAILED: no proof was attempted, so this is
            # not an SMP failure and must not be shown as one.  IDLE is also
            # what lets the user retry without a stale half-state.
            try:
                flow.reset()
            except _smpflow.SmpFlowError:
                pass
            return
        if not smp2:
            self.add_message(peer, colorize(
                "🔐 The held request is gone — ask them to run /smp again.",
                "yellow"), self._panel_sec(peer))
            try:
                flow.reset()
            except _smpflow.SmpFlowError:
                pass
            return
        # The engine has consumed the held message and produced the answer;
        # the flow stops being the holder of a request at this point and not
        # before, so a failure above leaves it answerable.
        flow.has_held_smp1 = False
        try:
            flow.running()
        except _smpflow.SmpFlowError:
            pass
        self.send_otr_message(peer, smp2)

    def _active_peer(self) -> Optional[str]:
        """The peer whose tab is in front, or None if it is not a peer tab.

        Five call sites spelled this out inline, identically.  Once is
        enough, and a shared helper means the "system and debug are not
        peers" rule cannot drift between them -- typing /smp on the system
        tab must not resolve to a peer named "system".
        """
        try:
            active = self.panel_manager.get_active_panel()
        except Exception:
            return None
        if active is None or active.type in ("system", "debug"):
            return None
        return active.name

    def _smp_session_ready(self, peer: str) -> bool:
        """Refuse to ask for a passphrase there is nothing to verify with.

        Fail-closed: a session_manager that raises counts as not ready.  The
        cost of getting this wrong is a user typing a shared secret at a
        prompt whose session does not exist.
        """
        try:
            if not self.session_manager.has_session(peer):
                self.add_message("system",
                                 f"{colorize ('❌ No session with','red')} {peer }")
                return False
            if (self.session_manager.get_security_level(peer)
                    == UIConstants.SecurityLevel.PLAINTEXT):
                self.add_message(
                    "system",
                    f"{colorize ('❌ No encrypted session with','red')} {peer }")
                return False
        except Exception:
            self.add_message("system", colorize(
                "❌ Could not check the session state — not asking for a "
                "passphrase.", "red"))
            return False
        return True

    def _warn_inline_secret(self, peer: str) -> None:
        """Say that an inline passphrase was echoed, because it was.

        The input line is cleared on Enter so it leaves the screen, but a
        `script` capture or a scrollback buffer recorded the keystrokes as
        they were echoed.  Better to say so than to let it look like it was
        never shown.  Same wording as the XMPP client's.
        """
        sec = self._panel_sec(peer)
        self.add_message(peer, colorize(
            "🔐 NOTE: that passphrase was typed in the clear, so it is in "
            "this terminal's scrollback and in any session capture.", "yellow"),
            sec)
        self.add_message(peer, colorize(
            "🔐 Bare  /smp  asks for it hidden instead.", "dim"), sec)

    def _check_smp_secret_required(self, peer: str) -> None:
        """Show the consent prompt if the engine is holding a peer's SMP1."""
        try:
            if not self.session_manager.smp_secret_required(peer):
                return
        except Exception:
            return
        self._announce_secret_required(peer)

    def _handle_trust_response(self, peer: str, response: str, action: dict):
        """Process y/n trust response from user."""
        trusted = response == "y"
        remote_fp = action.get("remote_fp", "")
        is_initiator = action.get("is_initiator", False)

        if trusted and remote_fp:
            try:
                if hasattr(self.session_manager, "trust_fingerprint"):
                    self.session_manager.trust_fingerprint(peer, remote_fp)
                else:
                    self.session_manager.trust_db.add_trust(peer, remote_fp)
            except Exception as exc:
                self.debug("trust save error")

        self._finish_trust(peer, trusted=trusted, remote_fp=remote_fp, is_initiator=is_initiator)

    def _finish_trust(self, peer: str, trusted: bool, remote_fp: str, is_initiator: bool):
        """Update security level after trust decision, then prompt for SMP secret."""
        if trusted:
            sec = UIConstants.SecurityLevel.FINGERPRINT
            self.add_message(peer, colorize("🟢 Fingerprint trusted - VERIFIED", "green"), sec)
        else:
            sec = UIConstants.SecurityLevel.ENCRYPTED
            self.add_message(
                peer, colorize("🟡 Fingerprint NOT trusted - encrypted only", "yellow"), sec
            )

        self.panel_manager.update_panel_security(peer, sec)

        self.add_message(peer, colorize("─" * 50, "dim"), sec)
        self.add_message(
            peer,
            colorize(
                "🔐 SMP VERIFICATION (🦀 Hybrid PQC: ML-KEM-1024 + ML-DSA-87 + ZKP)", "blue"
            ),
            sec,
        )
        # This used to end with _set_pending("smp_secret", peer, ...), which
        # made the NEXT LINE TYPED become the shared secret -- unmasked, into
        # scrollback -- and it was armed from here, which a remote peer
        # reaches by completing a DAKE.  A peer therefore decided what the
        # user's next sentence meant.  Same defect INV-06 was written for
        # after it was removed from the XMPP client; this side kept it.
        #
        # Nothing is armed now.  The user types /smp when they are ready, and
        # that command asks for the passphrase itself.
        self.add_message(
            peer,
            colorize("Type  /smp  when you are ready to verify. It will ask "
                     "for the passphrase you agreed with them.", "cyan"),
            sec,
        )
        self.add_message(
            peer,
            colorize("Until you do, what you type here is an ordinary "
                     "message.", "dim"),
            sec,
        )
        self._finish_session_setup(peer, sec)

    def _ensure_rust_smp(self, peer: str) -> None:
        """Ensure the Rust SMP engine is initialized for *peer*'s session."""
        session = (
            self.session_manager.get_session(peer)
            if hasattr(self.session_manager, "get_session")
            else None
        )
        if session is not None and hasattr(session, "initialize_smp"):
            session.initialize_smp()

    def _finish_session_setup(self, peer: str, sec):
        """Show final help after session is fully set up."""
        _session = (
            self.session_manager.get_session(peer)
            if hasattr(self.session_manager, "get_session")
            else None
        )
        _backend = getattr(_session, "_ratchet_backend", "python") if _session else "python"
        _ratchet_tag = "🦀 Rust" if _backend == "rust" else "🐍 Python"
        _dake_engine = getattr(_session, "dake_engine", None)
        _dake_tag = "🦀 Rust"
        _smp_tag = "🦀 Rust" if (getattr(_session, "rust_smp", None) is not None) else "🐍 Python"
        self._clear_no_session_warning(peer)
        self.add_message(peer, colorize("─" * 50, "dim"), sec)
        self._dake_ready(peer)
        # Which engine did the work stays on screen -- it is the difference
        # between the Rust ratchet and the Python fallback, and a user who
        # cares about that cares about it at exactly this moment -- but dim
        # and on one line rather than competing with the verdict above it.
        self.add_message(
            peer,
            colorize(
                f"   DAKE {_dake_tag } | Ratchet {_ratchet_tag } | SMP {_smp_tag }",
                "dim",
            ),
            sec,
        )
        self.add_message(
            "system",
            f"{colorize ('Commands:','cyan')} "
            f"/smp  (asks for the passphrase, hidden)  /fingerprint  "
            f"/trust <nick>  /secure",
        )

    def _handle_data_message(self, sender: str, payload: str):
        """Inbound OTR data message, plus the held-SMP1 check.

        The engine parks a peer's SMP1 when no passphrase is stored; nothing
        was asking it whether it had. Checked here, after the message has
        been processed, because that is the point at which the park has
        happened. Idempotent -- `_announce_secret_required` refuses to print
        a second prompt for the same peer.
        """
        result = OTRv4IRCClient._handle_data_message(self, sender, payload)
        try:
            self._check_smp_secret_required(sender)
        except Exception:
            self.debug("held-SMP1 check failed")
        return result

    def process_smp_message(self, sender: str, data: bytes):
        """DEAD CODE - disabled to prevent duplicate SMP dispatch.

        SMP is handled exclusively through _handle_data_message →
        session_manager.decrypt_message → _enh_handle_smp_tlv.
        This method must never be called directly.
        """
        self.debug("process_smp_message ignored (use decrypt_message path)")

    _NOTIF_COOLDOWN = 30

    # Known termux-notification option flags. Any argument NOT in this set is
    # treated as untrusted data (a title/body/id derived from a nick or channel)
    # and is sanitised before it can reach the subprocess.
    _TERMUX_FLAGS = frozenset(
        {
            "--title",
            "--content",
            "--priority",
            "--id",
            "--alert-once",
            "--vibrate",
            "--ongoing",
            "--group",
        }
    )

    @staticmethod
    def _termux_clean(value: str, maxlen: int = 256) -> str:
        """Neutralise untrusted text before it becomes a subprocess argument.

        Strips ANSI/CSI escape sequences and C0/C1 control characters (including
        NUL and newlines) so a hostile nick, channel, or message body cannot
        spoof a notification or smuggle terminal control codes, and caps the
        length so a single notification cannot be abused. Printable Unicode
        (including emoji) is preserved.
        """
        text = str(value)
        text = re.sub(r"\x1b\[[0-9;?]*[ -/]*[@-~]", "", text)
        text = "".join(
            ch for ch in text if ch == "\t" or (0x20 <= ord(ch) < 0x7F) or ord(ch) >= 0xA0
        )
        return text[:maxlen]

    def _termux_fire(self, args: list) -> None:
        """Run termux-notification in the background; swallow all errors.

        Every argument is hardened against option-injection: fixed flags pass
        through unchanged, while any value is sanitised and a non-flag value that
        begins with '-' is de-fanged, so attacker-controlled text can never be
        parsed by termux-notification as a command-line option.
        """
        try:
            import subprocess as _sp

            safe: list = []
            for a in args:
                a = self._termux_clean(a)
                if a not in self._TERMUX_FLAGS and a.startswith("-"):
                    a = " " + a
                safe.append(a)
            _sp.Popen(
                ["termux-notification"] + safe,
                stdout=_sp.DEVNULL,
                stderr=_sp.DEVNULL,
            )
        except Exception:
            pass

    def _termux_remove_notification(self, panel: str) -> None:
        """Dismiss the tray notification for *panel* (called on tab switch)."""
        try:
            import subprocess as _sp

            notif_id = "otrv4_" + self._termux_clean(panel.lstrip("#"), 64)
            _sp.Popen(
                ["termux-notification-remove", notif_id],
                stdout=_sp.DEVNULL,
                stderr=_sp.DEVNULL,
            )
        except Exception:
            pass

    def _termux_notify_message(self, panel: str, message: str) -> None:
        """Notify of a new message in a background tab (rate-limited per panel)."""
        _now = time.time()
        if not hasattr(self, "_last_notif"):
            self._last_notif = {}
        if _now - self._last_notif.get(panel, 0) < self._NOTIF_COOLDOWN:
            return
        self._last_notif[panel] = _now
        is_channel = panel.startswith("#")

        sec_level = UIConstants.SecurityLevel.PLAINTEXT
        if not is_channel:
            try:
                if hasattr(self, "session_manager") and self.session_manager.has_session(panel):
                    sec_level = self.session_manager.get_security_level(panel)
                elif panel in self.panel_manager.panels:
                    sec_level = self.panel_manager.panels[panel].security_level
            except Exception:
                pass
        is_encrypted = not is_channel and sec_level != UIConstants.SecurityLevel.PLAINTEXT
        sec_icon = UIConstants.SECURITY_ICONS.get(sec_level, "🔴")
        if is_channel:
            _notif_title = panel
            _notif_body = "New message in " + panel
        elif is_encrypted:
            _notif_title = sec_icon + " " + panel
            _notif_body = "New encrypted message from " + panel
        else:
            _notif_title = "🔴 " + panel
            _notif_body = "New plaintext message from " + panel
        args = [
            "--title",
            _notif_title,
            "--content",
            _notif_body,
            "--priority",
            "high" if is_encrypted else "default",
            "--id",
            "otrv4_" + panel.lstrip("#"),
            "--alert-once",
        ]
        if is_encrypted:
            args += ["--vibrate", "0,200,100,200"]
        self._termux_fire(args)

    def _termux_notify_otr_event(self, peer: str, started: bool) -> None:
        """Notify of OTR session start (🔒) or end (🔓)."""
        if started:
            self._termux_fire(
                [
                    "--title",
                    "🔒 OTR session started",
                    "--content",
                    "Encrypted session with " + peer + " established",
                    "--priority",
                    "high",
                    "--id",
                    "otrv4_" + peer + "_session",
                    "--vibrate",
                    "0,150,100,150,100,150",
                ]
            )
        else:
            self._termux_fire(
                [
                    "--title",
                    "🔓 OTR session ended",
                    "--content",
                    "Session with " + peer + " closed",
                    "--priority",
                    "default",
                    "--id",
                    "otrv4_" + peer + "_session",
                ]
            )

    def _on_peer_disconnected(self, peer: str, reason: str = "") -> None:
        """Tear down OTR session and update UI when a peer goes offline.

        Idempotent - _disconnected_peers set prevents duplicate messages
        from the 401 flood (one 401 per outbound fragment with no destination).
        """
        if peer not in self.panel_manager.panels:
            return
        if not hasattr(self, "_disconnected_peers"):
            self._disconnected_peers: set = set()
        if peer in self._disconnected_peers:
            return
        self._disconnected_peers.add(peer)

        sec = UIConstants.SecurityLevel.PLAINTEXT
        reason_str = f": {_sanitise (reason ,160 )}" if reason else ""
        self.add_message(
            peer, colorize(f"⚠ {peer } disconnected{reason_str } - OTR session ended", "red"), sec
        )
        # A peer killed for flooding is evidence about OUR send rate, not just
        # theirs.  Both ends of an OTRv4+ conversation run this client, at
        # whatever preset the pair agreed, and the messages are symmetrical:
        # if their 47-fragment SMP2 was too fast for this server, our SMP3 is
        # about to be too.  Seen on irc.postman.i2p -- the peer was killed
        # with "Excess Flood" while answering an SMP challenge, and this
        # client carried on at the same rate having learned nothing, because
        # only an ERROR addressed to us was being read as evidence.
        #
        # The reason string is attacker-controlled: a peer can /quit with any
        # text, including this one.  The worst that buys them is making us
        # slower, which is why acting on it is safe and why the rate is never
        # raised automatically in response to anything.
        self._note_peer_flood(peer, reason)

        self.panel_manager.update_panel_security(peer, sec)
        self.panel_manager.update_smp_progress(peer, 0, 0)

        try:
            if hasattr(self.session_manager, "terminate_session"):
                self.session_manager.terminate_session(peer, "peer disconnected")
            elif hasattr(self.session_manager, "sessions"):
                self.session_manager.sessions.pop(peer, None)
        except Exception:
            pass

        try:
            action = getattr(self, "_pending_action", None)
            if action and action.get("peer") == peer:
                self._pending_action = None
        except Exception:
            pass

    def _on_smp_verified(self, peer: str):
        """Called when SMP verification succeeds → 🔵 SMP_VERIFIED (fires once)."""
        if getattr(self, "_smp_verified_notified", {}).get(peer):
            return
        if not hasattr(self, "_smp_verified_notified"):
            self._smp_verified_notified = {}
        self._smp_verified_notified[peer] = True

        sec = UIConstants.SecurityLevel.SMP_VERIFIED
        self.panel_manager.update_panel_security(peer, sec)
        self.panel_manager.update_smp_progress(peer, 0, 0)
        self.add_message(
            self._otr_panel(peer),
            colorize(
                "🔵 SMP VERIFIED - identity confirmed by shared secret! (🦀 Rust SMP)", "blue"
            ),
            sec,
        )
        self.add_message(
            "system", f"{colorize ('🔵 SMP verified with','blue')} {colorize_username (peer )}"
        )
        self._termux_fire(
            [
                "--title",
                "\U0001f535 OTR identity verified",
                "--content",
                peer + " - SMP shared secret confirmed",
                "--priority",
                "high",
                "--id",
                "otrv4_" + peer + "_session",
                "--vibrate",
                "0,100,50,100",
            ]
        )

    def handle_message(self, line: str):
        """Dispatch IRC line - routes OTR fragments to process_incoming_otr_message."""
        try:
            prefix, command, params, trailing, _tags = self.parse_irc_message(line)
            self.logger.network_message("IN", prefix or "SERVER", command or "?", len(line))
            self.debug(
                "recv", {"cmd": command, "params": params[:3], "trail": (trailing or "")[:120]}
            )

            if command == "PING":
                self.send(f"PONG :{trailing or (params [0 ]if params else 'server')}")
                self.last_ping = time.time()
                return
            if command == "PONG":
                self.last_ping = time.time()
                return

            if command and command.isdigit():
                self.handle_numeric_reply(int(command), params, trailing)
                return

            sender = prefix.split("!")[0] if prefix and "!" in prefix else prefix or "server"
            if len(sender) > 50 or "\r" in sender or "\n" in sender:
                return
            if sender in self.ignored_users:
                return

            if command == "PRIVMSG":
                target = params[0] if params else ""
                message = trailing or ""

                if self.is_ctcp_message(message) and "?OTRv4" not in message:
                    return

                self.check_auto_reply(sender, target, message)

                if "?OTRv4" in message:

                    if hasattr(self, "_401_count"):
                        self._401_count.pop(sender, None)
                    if hasattr(self, "_401_handled"):
                        self._401_handled.discard(sender)
                    if hasattr(self, "_disconnected_peers"):
                        self._disconnected_peers.discard(sender)

                    self._dispatch_otr_fragment(sender, message)
                    return

                panel = target if target.startswith("#") else sender
                self.add_message(panel, f"{colorize_username (sender )}: {message }")
                return

            OTRv4IRCClient.handle_message(self, line)

        except Exception as exc:
            self.debug("handle_message error")

    def process_incoming_otr_message(self, sender: str, message: str):
        """Route a complete OTRv4 message to the right handler."""
        self.debug("otr msg", {"len": len(message)})
        try:
            if not message.startswith("?OTRv4 "):
                return

            raw = message[7:].strip()
            if not raw:
                return

            try:
                decoded = _safe_b64decode(raw)
            except Exception:
                return

            if not decoded:
                return

            if (
                OTRv4DataMessage.looks_like_data_frame(decoded)
            ):
                self.debug("otr type", {"type": "DATA_V6"})
                self._handle_data_message(sender, message)
                return

            msg_type = decoded[0]
            self.debug("otr type", {"type": msg_type})

            if msg_type == OTRConstants.MESSAGE_TYPE_DAKE1:
                self.process_dake1(sender, message)
            elif msg_type == OTRConstants.MESSAGE_TYPE_DAKE2:
                self.process_dake2(sender, message)
            elif msg_type == OTRConstants.MESSAGE_TYPE_DAKE3:
                self.process_dake3(sender, message)
            elif msg_type == OTRConstants.MESSAGE_TYPE_DATA:
                self._handle_data_message(sender, message)
        except Exception as exc:
            self.debug("process_incoming_otr error")

    def handle_chat_message(self, msg: str):
        """
        Intercept chat input.
        If a pending action is waiting, consume it.
        Otherwise encrypt+send normally.
        """
        # FIRST, and before any command parsing: a passphrase the user was
        # asked for locally. It goes first because the passphrase is
        # arbitrary text -- one that happens to begin with `/` is still the
        # passphrase, not a command. `_secret_request` is set only from a
        # typed /smp or a typed y, never by anything a peer sends (INV-06).
        if self._consume_secret_line(msg):
            return

        if self._dispatch_pending_response(msg):
            return

        OTRv4IRCClient.handle_chat_message(self, msg)

    def start_guided_otr_session(self, peer: str):
        """Start DAKE with peer by sending DAKE1."""
        if (
            self.session_manager.has_session(peer)
            and self.session_manager.get_security_level(peer) != UIConstants.SecurityLevel.PLAINTEXT
        ):
            if peer not in self.panel_manager.panels:
                self.panel_manager.add_panel(peer, "private")
            self._switch_panel(peer)
            self.add_message(
                peer, colorize(f"✅ Already encrypted with {colorize_username (peer )}", "green")
            )
            return

        if peer not in self.panel_manager.panels:
            self.panel_manager.add_panel(peer, "private")
        self._switch_panel(peer)
        self.add_message(
            peer, colorize(f"🔑 Starting OTR session with {colorize_username (peer )}…", "cyan")
        )

        try:
            otr_msg, should_send = self.session_manager.handle_outgoing_message(peer, "")
            if otr_msg and should_send:
                # OK is reported from the result of the send, not from having
                # attempted it: a DAKE1 that never left the socket is not a
                # completed stage.
                sent = self.send_otr_message(peer, otr_msg)
                self._dake_stage(
                    peer, 1, "ok" if sent else "could not send the request",
                    detail="sent — %d fragments"
                           % getattr(self, "_last_fragment_count", 0),
                    note="waiting for their answer…" if sent else "")
            else:
                self.send(f"PRIVMSG {peer } :?OTRv4 ")
        except Exception as exc:
            self.debug("start_guided_otr_session error")
            self._dake_stage(peer, 1, "%s" % type(exc).__name__)

    def handle_command(self, command: str):
        parts = command.strip().split()
        if not parts:
            return
        cmd = parts[0].lower()

        if cmd == "otr" and len(parts) > 1:
            self.start_guided_otr_session(parts[1])

        elif cmd == "trust" and len(parts) > 1:
            peer = parts[1]
            sec = (
                self.session_manager.get_security_level(peer)
                if self.session_manager.has_session(peer)
                else UIConstants.SecurityLevel.ENCRYPTED
            )
            remote_fp = self._get_remote_fp(peer)

            if remote_fp:
                try:
                    if hasattr(self.session_manager, "trust_fingerprint"):
                        self.session_manager.trust_fingerprint(peer, remote_fp)
                    else:
                        self.session_manager.trust_db.add_trust(peer, remote_fp)

                    new_sec = UIConstants.SecurityLevel.FINGERPRINT
                    self.panel_manager.update_panel_security(peer, new_sec)
                    self.add_message(
                        peer, colorize("🟢 Fingerprint trusted - VERIFIED", "green"), new_sec
                    )
                except Exception as exc:
                    self.add_message("system", f"{colorize ('❌ Trust failed:','red')} {exc }")
            else:
                self.add_message("system", colorize("No active session to trust", "red"))

        elif cmd in ("smp", "verify"):
            self._smp_command(parts)

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
                return
            try:
                if hasattr(self.session_manager, "set_smp_secret"):
                    self.session_manager.set_smp_secret(peer, secret)
                elif hasattr(self.session_manager, "smp_storage"):
                    self.session_manager.smp_storage.set_secret(peer, secret)

                self.add_message("system", f"🔑 SMP secret set for {colorize_username (peer )}")
                sec_level = self.session_manager.get_security_level(peer)
                self.add_message(
                    self._otr_panel(peer),
                    colorize("🔐 Type  /smp start  to begin verification.", "cyan"),
                    sec_level,
                )
            except Exception as exc:
                self.add_message("system", f"{colorize ('❌','red')} {exc }")

        elif cmd == "fingerprint":
            self._show_fingerprints()

        elif cmd in ("secure", "sessions", "otr-status"):
            self._show_all_sessions()

        elif cmd == "session-info" and len(parts) > 1:
            self._show_session_info(parts[1])

        elif cmd == "endotr" and len(parts) > 1:
            peer = parts[1]
            try:
                if hasattr(self.session_manager, "terminate_session"):
                    self.session_manager.terminate_session(peer, "user request")
                self.panel_manager.update_panel_security(peer, UIConstants.SecurityLevel.PLAINTEXT)
                self.add_message("system", f"Session ended with {colorize_username (peer )}")
            except Exception:
                pass

        else:
            OTRv4IRCClient.handle_command(self, command)

    def _smp_command(self, parts):
        """/smp and /verify: start, answer or report a verification for a nick."""
        # Bare /smp is the normal verb, and it has to be handled HERE.
        # v10.23.0 added it to OTRv4IRCClient.handle_command, but this
        # override claims "smp" before the `else` that delegates to the
        # base class, so what a user actually got on a handset was
        # "Usage: /smp <command> [args]" -- the guided flow existed and
        # was unreachable.  The tests that shipped with it bound the flow
        # methods onto a stub and never drove the dispatcher, so nothing
        # failed.  tests/test_irc_smp_command_routing.py drives it.
        if len(parts) < 2:
            peer = self._active_peer()
            if not peer:
                self.add_message("system", colorize(
                    "⚠ Switch to a peer panel first, then type /smp", "yellow"))
                return
            if not self._smp_session_ready(peer):
                return
            self._smp_verify(peer)
            return

        subcmd = parts[1].lower()

        if subcmd == "start":
            peer = parts[2] if len(parts) > 2 else self._active_peer()

            if not peer:
                self.add_message(
                    "system",
                    colorize("Usage: /smp start [peer]  (or switch to peer panel)", "red"),
                )
                return

            if not self.session_manager.has_session(peer):
                self.add_message("system", f"{colorize ('❌ No session with','red')} {peer }")
                return

            if (
                self.session_manager.get_security_level(peer)
                == UIConstants.SecurityLevel.PLAINTEXT
            ):
                self.add_message(
                    "system", f"{colorize ('❌ No encrypted session with','red')} {peer }"
                )
                return

            # Same as bare /smp.  This used to refuse with "use
            # /smp <peer> <secret> first" when nothing was stored, which
            # sent the user to the one form that puts a shared secret in
            # their own scrollback.  _smp_verify starts immediately when
            # a passphrase is stored and asks for it, hidden, when it is
            # not -- so the two spellings do the same thing, as they do
            # in the XMPP client.
            self.debug("Starting SMP")
            self._smp_verify(peer)

        elif subcmd == "abort":
            peer = parts[2] if len(parts) > 2 else self._active_peer()

            if not peer:
                self.add_message("system", colorize("Usage: /smp abort [peer]", "red"))
                return

            self.clear_pending_smp(peer)
            if hasattr(self.session_manager, "abort_smp"):
                self.session_manager.abort_smp(peer)
            self.add_message("system", f"🛑 SMP aborted for {colorize_username (peer )}")

        elif subcmd == "status":
            peer = parts[2] if len(parts) > 2 else self._active_peer()

            if not peer:
                self.add_message("system", colorize("Usage: /smp status [peer]", "red"))
                return

            self._show_smp_status(peer)

        else:
            peer = self._active_peer()

            if not peer and len(parts) > 2:
                peer = parts[1]
                secret = " ".join(parts[2:])
            elif peer:
                secret = " ".join(parts[1:])
            else:
                self.add_message(
                    "system",
                    colorize(
                        "Usage: /smp <peer> <secret>  or  /smp <secret> (in peer panel)", "red"
                    ),
                )
                return

            if secret:
                if len(secret) < 8:
                    self.add_message(
                        "system",
                        colorize(
                            f"⚠ SMP secret rejected - only {len (secret )} chars. "
                            "Minimum 8 required to resist brute-force attacks.",
                            "red",
                        ),
                    )
                    return
                try:
                    if hasattr(self.session_manager, "set_smp_secret"):
                        self.session_manager.set_smp_secret(peer, secret)
                    elif hasattr(self.session_manager, "smp_storage"):
                        self.session_manager.smp_storage.set_secret(peer, secret)

                    sec_level = self.session_manager.get_security_level(peer)
                    self.add_message(
                        self._otr_panel(peer),
                        colorize("✅ SMP secret stored (🦀 Rust vault)", "green"),
                        sec_level,
                    )
                    self._warn_inline_secret(peer)
                    # Verify now.  Storing and then telling the user to
                    # type a second command was a step with no decision
                    # in it: nobody types /smp <secret> meaning "store
                    # this but do not verify" -- that is /smp-secret.
                    #
                    # Through _smp_verify rather than straight into
                    # _start_smp, so this spelling cannot start a second
                    # run while the engine is holding a peer's SMP1: it
                    # reads the passphrase just stored, and in every
                    # other flow state it says what is already pending
                    # instead of talking over it.
                    self._smp_verify(peer)
                except Exception as exc:
                    self.add_message("system", f"{colorize ('❌','red')} {exc }")
                finally:
                    secret = None
            else:
                self.add_message(
                    "system", colorize("Usage: /smp <secret>  or  /smp start [peer]", "red")
                )

    def _start_smp(self, peer: str, secret: str, question: str = ""):
        """Kick off SMP verification with immediate step-1 feedback.

        The ZK proof computation inside rust_smp.generate_smp1() runs in Rust
        (hundreds of ms on Termux).  We show the step-1 progress bar to the
        user BEFORE starting the computation so they get instant feedback,
        then do the heavy work in a background thread.

        Security: set_smp_secret() is called here (main thread) which stores
        bytes in the Rust vault and immediately wipes the bytearray.  The
        background thread calls start_smp() with the already-bound vault -
        no plaintext string is captured in the closure.
        """
        if not self.session_manager.has_session(peer):
            self.add_message("system", f"{colorize ('❌ No session with','red')} {peer }")
            return

        if self.session_manager.get_security_level(peer) == UIConstants.SecurityLevel.PLAINTEXT:
            self.add_message("system", f"{colorize ('❌ No encrypted session with','red')} {peer }")
            return

        sess = self.session_manager.get_session(peer)
        if sess is not None and getattr(sess, "_smp_notify_cb", None) is None:
            factory = getattr(self.session_manager, "smp_notify_factory", None)
            if factory is not None:
                try:
                    sess._smp_notify_cb = factory(peer)
                except Exception:
                    pass

        sec = self.session_manager.get_security_level(peer)
        self.add_message(
            peer,
            colorize(
                "🔐 SMP [███ ░░░ ░░░ ░░░] step 1/4 (🦀 Rust SMP)"
                " · Computing challenge (ML-KEM-1024 + ML-DSA-87 + ZKP) - please wait…",
                "yellow",
            ),
            sec,
        )
        self.panel_manager.update_smp_progress(peer, 1, 4)

        if secret is None:
            # The stored auto-respond passphrase: bound store -> vault inside
            # Rust, never read back into this process.
            if not self.session_manager.bind_stored_smp_secret(peer):
                self.add_message("system", colorize(
                    "❌ No stored passphrase for %s" % peer, "red"))
                self.panel_manager.update_smp_progress(peer, 0, 0)
                return
        elif hasattr(self.session_manager, "set_smp_secret"):
            self.session_manager.set_smp_secret(peer, secret)

        secret = None

        def _do_smp():
            try:
                if not hasattr(self.session_manager, "start_smp"):
                    self.add_message(
                        "system", colorize("SMP not supported by session manager", "red")
                    )
                    return

                self.debug("SMP background compute starting")
                try:

                    encrypted_msg = self.session_manager.start_smp(peer, "", question)
                except Exception as smp_exc:
                    self.debug("SMP start exception")
                    self.add_message(
                        "system", colorize(f"❌ SMP failed: {str (smp_exc )[:200 ]}", "red")
                    )
                    self.panel_manager.update_smp_progress(peer, 0, 0)
                    return
                self.debug(f"SMP compute done: msg={'yes'if encrypted_msg else 'no'}")

                if (
                    encrypted_msg
                    and isinstance(encrypted_msg, str)
                    and encrypted_msg.startswith("?OTRv4 ")
                ):
                    if self.send_otr_message(peer, encrypted_msg):
                        s = self.session_manager.get_security_level(peer)
                        self.add_message(
                            peer,
                            colorize(
                                "🔐 SMP [███ ░░░ ░░░ ░░░] step 1/4 (🦀 Rust SMP)"
                                " · Challenge sent - awaiting response…",
                                "yellow",
                            ),
                            s,
                        )
                    else:
                        self.add_message(
                            "system", colorize("❌ Failed to send SMP challenge", "red")
                        )
                        self.panel_manager.update_smp_progress(peer, 0, 0)
                else:
                    self.panel_manager.update_smp_progress(peer, 0, 0)
                    if hasattr(self.session_manager, "get_smp_status"):
                        status = self.session_manager.get_smp_status(peer)
                        if status.get("verified"):
                            self.add_message(
                                peer,
                                colorize("✅ SMP already verified!", "green"),
                                self.session_manager.get_security_level(peer),
                            )
                        elif status.get("state") not in ("NONE", "FAILED"):
                            self.add_message(
                                peer,
                                colorize(
                                    f"⚠ SMP already in progress (state: {status .get ('state')})",
                                    "yellow",
                                ),
                                self.session_manager.get_security_level(peer),
                            )
                        else:
                            self.add_message(
                                "system",
                                colorize("❌ SMP init failed - check session state", "red"),
                            )
            except Exception as exc:
                self.debug("_start_smp background error")
                self.add_message("system", colorize(f"❌ SMP error: {str (exc )[:80 ]}", "red"))
                self.panel_manager.update_smp_progress(peer, 0, 0)

        threading.Thread(target=_do_smp, daemon=True, name=f"smp-{peer }").start()

    def _get_local_fp(self) -> str:
        try:
            if hasattr(self.session_manager, "get_fingerprint"):
                fp = self.session_manager.get_fingerprint()
                if fp:
                    return fp
            if hasattr(self.session_manager, "client_profile"):
                return self.session_manager.client_profile.get_fingerprint()
        except Exception:
            pass
        return "unavailable"

    def _get_remote_fp(self, peer: str) -> str:
        """Get remote fingerprint for peer using multiple fallback methods."""
        try:
            if hasattr(self.session_manager, "get_peer_fingerprint"):
                fp = self.session_manager.get_peer_fingerprint(peer)
                if fp:
                    self.debug("_get_remote_fp: fingerprint obtained")
                    return fp

            sess = self.session_manager.get_session(peer)
            if sess:
                if hasattr(sess, "get_fingerprint"):
                    fp = sess.get_fingerprint()
                    if fp:
                        self.debug(
                            f"_get_remote_fp: got from session.get_fingerprint: {fp [:16 ]}..."
                        )
                        return fp

                if hasattr(sess, "remote_long_term_pub") and sess.remote_long_term_pub:
                    try:

                        pub_bytes = bytes(sess.remote_long_term_pub)
                        fp_bytes = hashlib.sha3_512(pub_bytes).digest()
                        fp = fp_bytes.hex().upper()
                        self.debug("_get_remote_fp: fingerprint obtained")
                        return fp
                    except Exception as e:
                        self.debug("_get_remote_fp: conversion failed")

                if (
                    hasattr(sess, "_remote_long_term_pub_bytes")
                    and sess._remote_long_term_pub_bytes
                ):
                    try:
                        fp_bytes = hashlib.sha3_512(sess._remote_long_term_pub_bytes).digest()
                        fp = fp_bytes.hex().upper()
                        self.debug("_get_remote_fp: fingerprint obtained")
                        return fp
                    except Exception as e:
                        self.debug("_get_remote_fp: stored conversion failed")

        except Exception as e:
            self.debug("_get_remote_fp error")

        self.debug("_get_remote_fp: no fingerprint found")
        return ""

    @staticmethod
    def _fmt_fp(fp: str) -> str:
        """Format 40-char fingerprint as groups of 8."""
        if not fp or fp == "unavailable":
            return fp
        clean = fp.upper().replace(" ", "")
        if len(clean) < 40:
            clean = clean.ljust(40, "0")
        return " ".join(clean[i : i + 8] for i in range(0, 40, 8))

    def _show_fingerprints(self):
        local_fp = self._get_local_fp()
        self.add_message(
            "system", f"Your fingerprint: {colorize (self ._fmt_fp (local_fp ),'cyan')}"
        )

        for peer in list(self.session_manager.sessions.keys()):
            fp = self._get_remote_fp(peer)
            sec = self.session_manager.get_security_level(peer)
            icon = UIConstants.SECURITY_ICONS.get(sec, "")
            trusted = ""

            if fp:
                try:
                    is_t = (
                        self.session_manager.is_peer_trusted(peer)
                        if hasattr(self.session_manager, "is_peer_trusted")
                        else self.session_manager.trust_db.is_trusted(peer, fp)
                    )
                    trusted = (
                        colorize(" ✅ trusted", "green")
                        if is_t
                        else colorize(" ⚠ untrusted", "yellow")
                    )
                except Exception:
                    trusted = ""

            self.add_message(
                "system",
                f"  {icon } {colorize_username (peer )}: "
                f"{colorize (self ._fmt_fp (fp ),'green')}{trusted }",
            )

    def _show_all_sessions(self):
        sessions = self.session_manager.sessions
        if not sessions:
            self.add_message("system", "No OTR sessions active")
            return

        self.add_message("system", colorize("Active OTR sessions:", "cyan"))
        for peer, sess in sessions.items():
            sec = getattr(sess, "security_level", UIConstants.SecurityLevel.PLAINTEXT)
            icon = UIConstants.SECURITY_ICONS.get(sec, "")
            name = UIConstants.SECURITY_NAMES.get(sec, sec.name)
            _dake_engine = getattr(sess, "dake_engine", None)
            _dake_tag = "🦀R"
            _ratchet_backend = getattr(sess, "_ratchet_backend", "python")
            _ratchet_tag = "🦀R" if _ratchet_backend == "rust" else "🐍Py"
            _smp_tag = "🦀R" if getattr(sess, "rust_smp", None) is not None else "🐍Py"
            self.add_message(
                "system",
                f"  {icon } {colorize_username (peer ):<20} {colorize (name ,'yellow')}  "
                f"[DAKE {_dake_tag } | Ratchet {_ratchet_tag } | SMP {_smp_tag }]",
            )

    def _show_session_info(self, peer: str):
        if not self.session_manager.has_session(peer):
            self.add_message("system", f"{colorize ('No session with','red')} {peer }")
            return

        info = self.session_manager.get_session_info(peer)
        for k, v in info.items():
            self.add_message("system", f"  {k }: {v }")

    def _show_smp_status(self, peer: str):
        if not self.session_manager.has_session(peer):
            self.add_message("system", f"{colorize ('No session with','red')} {peer }")
            return

        if hasattr(self.session_manager, "get_smp_status"):
            status = self.session_manager.get_smp_status(peer)
            _sess = self.session_manager.get_session(peer)
            _smp_tag = "🦀 Rust" if (getattr(_sess, "rust_smp", None) is not None) else "🐍 Python"
            self.add_message("system", f"SMP {colorize_username (peer )} [{_smp_tag }]: {status }")

    def shutdown(self):
        """Shutdown client with complete terminal clear"""
        self.add_message("system", colorize("🔄 Shutting down OTR sessions…", "yellow"))

        _session_count = (
            len(self.session_manager.sessions) if hasattr(self.session_manager, "sessions") else 0
        )
        _rust_count = 0

        try:
            if hasattr(self.session_manager, "sessions"):
                for peer, sess in self.session_manager.sessions.items():
                    if getattr(sess, "_ratchet_backend", None) == "rust":
                        _rust_count += 1
        except Exception:
            pass

        try:
            if hasattr(self.session_manager, "clear_all_sessions"):
                self.session_manager.clear_all_sessions("client shutdown")
        except Exception:
            pass

        if _rust_count > 0:
            self.add_message(
                "system",
                colorize(
                    f"🦀 {_rust_count } Rust ratchet(s) zeroized (deterministic memory wipe)",
                    "green",
                ),
            )
        elif _session_count > 0:
            self.add_message(
                "system",
                colorize(
                    f"🐍 {_session_count } Python ratchet(s) cleaned (GC-dependent)", "yellow"
                ),
            )

        try:
            cl = getattr(self, "channel_log", None)
            if cl is not None:
                cl.close()
                self.channel_log = None
        except Exception:
            pass

        self._secure_wipe_data()

        try:
            OTRv4IRCClient.shutdown(self)
        except Exception:
            pass

        try:
            sys.stdout.write("\033[2J")
            sys.stdout.write("\033[H")
            sys.stdout.write("\033[3J")
            sys.stdout.flush()

            print("\n" * 100)

            try:
                import subprocess as _subp

                _subp.run(["clear"], check=False)
            except Exception:
                pass

            _wipe_msg = "🦀 Rust memory zeroized" if RUST_RATCHET_AVAILABLE else "Memory cleared"
            print(colorize(f"\nOTRv4+ terminated - {_wipe_msg } - screen cleared", "green"))
            print(colorize("Type 'python otrv4+.py --debug' to start again", "cyan"))

        except Exception as e:
            self.debug(f"Error clearing screen: {e }")

    def _secure_wipe_data(self):
        """Overwrite and remove all persisted OTR data under ~/.otrv4plus.

        Each file is overwritten once with random bytes, fsynced and
        unlinked (`_secure_file_destroy`), then the directory is removed.
        That makes the data unrecoverable through the file system. It does
        NOT guarantee the old physical blocks are erased on flash storage:
        wear-levelling keeps them out of reach of any file-level call. The
        earlier claim here -- that recovered blocks would be ciphertext
        under a destroyed key -- was wrong; the old blocks hold the old data.
        """
        import glob

        otrv4plus_dir = os.path.expanduser("~/.otrv4plus")

        try:
            os.makedirs(otrv4plus_dir, exist_ok=True)
            os.chmod(otrv4plus_dir, 0o700)
        except Exception:
            pass

        wiped = 0
        failed = 0

        try:
            if os.path.isdir(otrv4plus_dir):
                for fpath in glob.glob(os.path.join(otrv4plus_dir, "**", "*"), recursive=True):
                    if os.path.isfile(fpath):
                        try:
                            _real = os.path.realpath(fpath)
                            _base = os.path.realpath(otrv4plus_dir)
                            if not _real.startswith(_base + os.sep) and _real != _base:
                                continue
                        except Exception:
                            continue
                        try:
                            _secure_file_destroy(fpath)
                            wiped += 1
                        except Exception:
                            try:
                                os.remove(fpath)
                            except Exception:
                                pass
                            failed += 1

                import shutil

                shutil.rmtree(otrv4plus_dir, ignore_errors=True)

                status = f"🗑  ~/.otrv4plus wiped - {wiped } file(s) overwritten and removed"
                if failed:
                    status += f" ({failed } fallback)"
                self.add_message("system", colorize(status, "green"))
        except Exception as e:
            self.add_message("system", colorize("⚠ Wipe incomplete", "yellow"))


def parse_args() -> OTRConfig:
    """Parse command line arguments"""
    config = OTRConfig()

    if "--help" in sys.argv or "-h" in sys.argv:
        print("""
OTRv4+ - Post-quantum encrypted IRC client

Usage: python otrv4+.py [options]

Connection:
  -s, --server HOST[:PORT]   Server to connect to (default: irc.postman.i2p)
  -p, --port PORT            Server port (default: auto - 6697 TLS, 6667 plain)
  -c, --channel #CHANNEL     Channel to auto-join (default: #otr)
  -n, --nick NICK            Nickname (default: random from pool)
      --tls                  Force TLS on
      --no-tls               Disable TLS (for Tor/I2P only - clearnet auto-uses TLS)

Authentication:
      --sasl                 SASL login (prompts for nick + password)
      --login                NickServ login (prompts for nick + password)

Debug:
  -d, --debug                Enable debug output
      --smp-debug            Enable SMP protocol debug output

Network auto-detection:
  *.i2p    → I2P SAM bridge (preferred) or SOCKS5 fallback
  *.onion  → Tor SOCKS5 on 127.0.0.1:9050
  other    → Direct connection with TLS

Examples:
  python otrv4+.py                           # I2P default (irc.postman.i2p)
  python otrv4+.py -s irc.libera.chat:6697   # Clearnet with TLS
  python otrv4+.py -s irc.postman.i2p -c #i2p-chat
  python otrv4+.py --sasl -n YourNick -s irc.libera.chat:6697
  python otrv4+.py -s somehidden.onion --no-tls

Once connected, type /help for in-client commands.
Type /help mode for IRC user modes (+g, +i, etc).
""")
        sys.exit(0)

    if "--debug" in sys.argv or "-d" in sys.argv:

        _engine.DEBUG_MODE = True

    if "--smp-debug" in sys.argv:

        _engine.SMP_DEBUG = True

    for i, arg in enumerate(sys.argv):
        if arg in ("--server", "-s") and i + 1 < len(sys.argv):
            config.server = sys.argv[i + 1]
        elif arg in ("--channel", "-c") and i + 1 < len(sys.argv):
            config.channel = sys.argv[i + 1]
        elif arg in ("--nick", "-n") and i + 1 < len(sys.argv):
            config.nickserv_nick = sys.argv[i + 1]
        elif arg in ("--port", "-p") and i + 1 < len(sys.argv):
            _pval = int(sys.argv[i + 1])
            if not 1 <= _pval <= 65535:
                print(f"Error: --port must be 1-65535 (got {_pval })")
                sys.exit(1)
            config.port = _pval
        elif arg == "--tls":
            config.use_tls = True
        elif arg == "--no-tls":
            config.use_tls = False
            if config.port == 0:
                config.port = IRCConstants.PORT

    if ":" in config.server:
        _parts = config.server.rsplit(":", 1)
        if _parts[1].isdigit():
            config.server = _parts[0]
            if config.port == 0:
                config.port = int(_parts[1])

    if "--sasl" in sys.argv:
        if not config.nickserv_nick:
            config.nickserv_nick = input("Nick: ").strip()
        if not config.nickserv_nick:
            print("Error: nick required for --sasl")
            sys.exit(1)
        config.sasl_user = config.nickserv_nick
        config.sasl_pass = getpass.getpass("SASL password: ")
        if not config.sasl_pass:
            print("Error: password required for --sasl")
            sys.exit(1)

    elif "--login" in sys.argv:
        config.nickserv_login = True
        if not config.nickserv_nick:
            config.nickserv_nick = input("Nick: ").strip()
        if not config.nickserv_nick:
            print("Error: nick required for --login")
            sys.exit(1)
        config.nickserv_pass = getpass.getpass("NickServ password: ")
        if not config.nickserv_pass:
            print("Error: password required for --login")
            sys.exit(1)

    elif "--register" in sys.argv:
        config.nickserv_register = True
        if not config.nickserv_nick:
            config.nickserv_nick = input("Choose nick: ").strip()
        if not config.nickserv_nick:
            print("Error: nick required for --register")
            sys.exit(1)
        config.nickserv_pass = getpass.getpass("Choose password: ")
        if not config.nickserv_pass:
            print("Error: password required for --register")
            sys.exit(1)
        pass2 = getpass.getpass("Confirm password: ")
        if config.nickserv_pass != pass2:
            print("Error: passwords do not match")
            sys.exit(1)

    return config


def _remove_legacy_files():
    """Overwrite and remove the vault, SMP-secrets file and key directory that
    older versions kept under ~/.otrv4*."""
    _legacy_orphan_paths = [
        os.path.expanduser("~/.otrv4_vault"),
        os.path.expanduser("~/.otrv4_smp_secrets.json"),
    ]
    for _orphan in _legacy_orphan_paths:
        try:
            if os.path.exists(_orphan):
                _secure_file_destroy(_orphan)
                if _engine.DEBUG_MODE:
                    print(f"[startup] overwrote and removed legacy file: {_orphan }")
        except Exception as _e:
            if _engine.DEBUG_MODE:
                print(f"[startup] could not destroy legacy file {_orphan }: {_e }")

    _legacy_keys_dir = os.path.expanduser("~/.otrv4_keys")
    try:
        if os.path.isdir(_legacy_keys_dir):
            import shutil as _shutil

            for _root, _dirs, _files in os.walk(_legacy_keys_dir):
                for _fn in _files:
                    try:
                        _secure_file_destroy(os.path.join(_root, _fn))
                    except Exception:
                        pass
            try:
                _shutil.rmtree(_legacy_keys_dir, ignore_errors=True)
            except Exception:
                pass
            if _engine.DEBUG_MODE:
                print(f"[startup] removed legacy directory: {_legacy_keys_dir }")
    except Exception as _e:
        if _engine.DEBUG_MODE:
            print(f"[startup] could not remove legacy keys dir: {_e }")


def _print_banner(config):
    """The start-up summary. Returns an exit code when the client must not
    start (no Rust core; the old self-test flag), otherwise None."""
    _net = NetworkConstants.detect(config.server)
    _net_icon = {"i2p": "🧅 I2P", "tor": "🧅 Tor", "clearnet": "🌐 Clearnet"}.get(_net, _net)
    _net_col = {"i2p": "dark_cyan", "tor": "dark_magenta", "clearnet": "grey"}.get(_net, "white")

    _disp_port = (
        config.port
        if config.port != 0
        else (IRCConstants.TLS_PORT if _net == "clearnet" else IRCConstants.PORT)
    )
    _tls_disp = (
        "🔒 TLS"
        if (_net == "clearnet" and _disp_port == IRCConstants.TLS_PORT) or config.use_tls
        else "plaintext"
    )
    _auth_disp = "SASL" if config.sasl_user else ("NickServ" if config.nickserv_login else "none")

    safe_print(f"\n{colorize ('OTRv4 IRC Client','bold_cyan')}")
    safe_print(colorize("=" * 50, "dim"))
    safe_print(f"Version : {colorize (VERSION ,'yellow')}")
    safe_print(f"Server  : {colorize (config .server +':'+str (_disp_port ),'green')}")
    safe_print(f"Network : {colorize (_net_icon ,_net_col )} ({_tls_disp })")
    safe_print(f"Auth    : {colorize (_auth_disp ,'cyan')}")
    safe_print(f"Channel : {colorize (config .channel ,'cyan')}")
    safe_print(
        f"Debug   : {colorize ('ON'if _engine.DEBUG_MODE else 'OFF','green'if _engine.DEBUG_MODE else 'dim')}"
    )
    _rt_label = "🦀 Rust (zeroize-on-drop)" if RUST_RATCHET_AVAILABLE else "❌ NOT INSTALLED"
    safe_print(f"Ratchet : {colorize (_rt_label ,'green'if RUST_RATCHET_AVAILABLE else 'red')}")
    _dake_label = (
        "🦀 Rust (DH secrets never Python)" if RUST_DAKE_AVAILABLE else "🐍 Python (C extensions)"
    )
    safe_print(f"DAKE    : {colorize (_dake_label ,'green'if RUST_DAKE_AVAILABLE else 'yellow')}")

    _smp_label = (
        "🦀 Rust (ML-KEM-1024 + ML-DSA-87 hybrid PQC, ZeroizeOnDrop)"
        if RUST_RATCHET_AVAILABLE
        else "🐍 Python (C extensions)"
    )
    safe_print(f"SMP     : {colorize (_smp_label ,'green'if RUST_RATCHET_AVAILABLE else 'yellow')}")

    if not RUST_RATCHET_AVAILABLE:
        safe_print(colorize("\n❌ FATAL: otrv4_core Rust module not installed.", "red"))
        safe_print(colorize("   Encrypted sessions require the Rust ratchet core.", "red"))
        safe_print(colorize("   Build with:", "yellow"))
        safe_print(
            colorize("     cd Rust && cargo test --release && maturin build --release", "cyan")
        )
        safe_print(colorize("     pip install target/wheels/otrv4_core-*.whl", "cyan"))
        safe_print("")
        return 1

    _net_detect = NetworkConstants.detect(config.server)
    if _net_detect == NetworkConstants.NET_I2P:
        _sam_host, _sam_port = config.i2p_sam
        _sam_ok = I2PSAMConnection.is_available(_sam_host, _sam_port)
        if _sam_ok:
            safe_print(
                f"I2P     : {colorize ('SAM bridge (unique destination per session)','green')}"
            )
        else:
            safe_print(
                f"I2P     : {colorize ('SOCKS5 (shared destination - SAM not available)','yellow')}"
            )

    safe_print(colorize("=" * 50, "dim") + "\n")

    if TEST_MODE:
        safe_print(colorize("Tests are now run via pytest:", "cyan"))
        safe_print(colorize("  pytest -v -k 'not 300k'", "green"))
        safe_print(colorize("  (207 tests across 9 test files)", "dim"))
        return 0
    return None


def _print_prompt(client):
    """Print the input prompt - called once per input cycle.

    Format:  [active-panel]  notif-badges  smp-bar
    Example: [#otr]  user201+3 sys+1  ⬤⬤◯◯

    The notification badges after the panel bracket show unread counts
    for every background panel so the user knows what's waiting without
    having to run /tabs.
    """
    active = client.panel_manager.get_active_panel()
    if not active:
        _set_prompt(colorize("> ", "green"))
        return
    sec_lvl = active.security_level
    if active.type in ("private", "secure"):
        icon = UIConstants.SECURITY_ICONS.get(sec_lvl, "🔴")
    else:
        icon = ""

    if active.type in ("private", "secure"):
        type_sym = ""
    elif active.type == "channel":
        type_sym = ""
    elif active.type == "system":
        type_sym = "⚙"
    elif active.type == "debug":
        type_sym = "🐛"
    else:
        type_sym = ""

    smp_inset = ""
    step, total = active.smp_progress
    if 0 < step < total:
        bar = "⬤" * step + "◯" * (total - step)
        smp_inset = colorize(f" {bar } ", "yellow")

    nick = getattr(client, "nick", "")
    bracket = f"{type_sym }{icon }{active .name }"
    prompt = (
        colorize(nick, "cyan")
        + colorize(" | ", "dim")
        + colorize(f"[{bracket }]", "green")
        + smp_inset
        + " "
    )
    _set_prompt(prompt)


def _run_input_loop(client, _select):
    """Read the keyboard until the user quits, then hand back to main."""

    client._prompt_refresh_cb = lambda: _print_prompt(client)

    try:
        _print_prompt(client)
        _use_raw = _setup_raw_mode()
        if _use_raw:
            atexit.register(_restore_terminal)
        _fd = _engine._stdin_fd if _use_raw else sys.stdin.fileno()

        def _read_line_raw() -> Optional[str]:
            """Read one char in raw mode.

            Returns str (completed line) when the user presses Enter,
            _EOF_SENTINEL on Ctrl-D, or None (char consumed, keep reading).
            """
            ch = _read_one_char()
            if ch is None:
                return _EOF_SENTINEL
            return _handle_input_char(ch)

        def _read_line_cooked() -> Optional[str]:
            """Read a full line in cooked mode (fallback for non-TTY)."""

            line = sys.stdin.readline()
            _engine._current_prompt = ""
            _flush_display_queue()
            if not line:
                return _EOF_SENTINEL
            return line.rstrip("\r\n")

        _read_input = _read_line_raw if _use_raw else _read_line_cooked

        while not client.shutdown_flag:
            try:
                r, _, _ = _select.select([_fd], [], [], 0.2)

                if not r:
                    _flush_display_queue()

                    if not client.running and not client.shutdown_flag and not client._reconnecting:
                        safe_print(
                            colorize(
                                "\n⚠ Disconnected from server. "
                                "Type /reconnect to reconnect, or /quit to exit.",
                                "yellow",
                            )
                        )
                        while (
                            not client.shutdown_flag
                            and not client.running
                            and not client._reconnecting
                        ):
                            try:
                                r2, _, _ = _select.select([_fd], [], [], 0.5)
                                if not r2:
                                    continue
                                result = _read_input()
                                if result is _EOF_SENTINEL:
                                    client.shutdown_flag = True
                                    break
                                if result is None:
                                    continue
                                l2 = result
                                if l2.startswith("/"):
                                    client.handle_command(l2[1:])
                                elif l2:
                                    safe_print(
                                        colorize("Not connected - use /reconnect first.", "yellow")
                                    )
                                _print_prompt(client)
                            except KeyboardInterrupt:
                                safe_print(colorize("\nCtrl-C - type /quit to exit", "yellow"))
                                _print_prompt(client)
                            except Exception:
                                pass
                        continue
                    continue

                result = _read_input()
                if result is _EOF_SENTINEL:
                    safe_print(colorize("\nEOF - shutting down", "yellow"))
                    break
                if result is None:
                    continue

                line = result

                if not line:
                    _print_prompt(client)
                    continue

                try:
                    _ap = client.panel_manager.active_panel
                    _pp = client.panel_manager.panels.get(_ap)
                    if _pp and _pp.panel_type == "private":
                        client.send_raw(f"@+typing=done TAGMSG {_ap }")
                except Exception:
                    pass
                if line.startswith("/"):
                    client.handle_command(line[1:])
                else:
                    client.handle_chat_message(line)

                if getattr(client, "_tui_enabled", False) and client._screen is not None:
                    client._screen.redraw_full()
                else:
                    _print_prompt(client)

            except KeyboardInterrupt:
                safe_print(colorize("\nCtrl-C - type /quit to exit", "yellow"))
                _print_prompt(client)
            except Exception as exc:
                try:
                    client.debug(f"main loop error: {exc }")
                    client.add_message(
                        "system",
                        colorize(f"⚠ Internal error (recovered): {str (exc )[:80 ]}", "yellow"),
                    )
                except Exception:
                    pass
                _print_prompt(client)

    except Exception as exc:
        try:
            safe_print(colorize("⚠ Critical error (attempting recovery)", "yellow"))
            while True:
                try:
                    r, _, _ = _select.select([_fd], [], [], 1.0)
                    if r:
                        if _use_raw:
                            ch = _read_one_char()
                            if ch is None:
                                break
                            res = _handle_input_char(ch)
                            if res is _EOF_SENTINEL:
                                break
                            if isinstance(res, str) and res.startswith("/quit"):
                                break
                            if res is None:
                                continue
                        else:
                            l = sys.stdin.readline()
                            if not l:
                                break
                            l = l.rstrip("\r\n")
                            if l.startswith("/quit"):
                                break
                        safe_print(colorize("Emergency mode - type /quit to exit", "yellow"))
                except Exception:
                    break
        except Exception:
            pass


def main():
    import select as _select



    config = parse_args()

    config.trust_db_path = os.path.expanduser("~/.otrv4plus/trust.json")
    config.smp_secrets_path = os.path.expanduser("~/.otrv4plus/smp_secrets.json")
    config.key_storage_path = os.path.expanduser("~/.otrv4plus/keys")
    config.log_file_path = os.path.expanduser("~/.otrv4plus/logs/otrv4plus.log")
    config.test_mode = TEST_MODE
    config.i2p_proxy = (NetworkConstants.I2P_PROXY_HOST, NetworkConstants.I2P_PROXY_PORT)
    config.tor_proxy = (NetworkConstants.TOR_PROXY_HOST, NetworkConstants.TOR_PROXY_PORT)
    config.log_level = "DEBUG" if _engine.DEBUG_MODE else "INFO"
    config.dake_timeout = 120.0
    config.fragment_timeout = 120.0
    config.heartbeat_interval = 60
    config.rekey_interval = 100
    _remove_legacy_files()

    code = _print_banner(config)
    if code is not None:
        return code

    client = EnhancedOTRv4IRCClient(config)
    import builtins as _b

    _b._active_client = client

    if not client.connect():
        _fail_net = NetworkConstants.detect(config.server)
        _fail_hints = {
            NetworkConstants.NET_TOR: (
                "Failed to connect via Tor.\n"
                "  • Desktop: ensure tor is running  (systemctl start tor)\n"
                "  • Android: start Orbot and tap 'Start'\n"
                "  • Tor Browser: make sure it is open (SOCKS5 on 9150)\n"
                "  Probed ports: 9050, 9150."
            ),
            NetworkConstants.NET_I2P: (
                "Failed to connect via I2P - is i2pd running?\n"
                "  Check: i2pd SOCKS5 port 4447, SAM port 7656."
            ),
            NetworkConstants.NET_CLEARNET: (
                "Failed to connect - check server address and network."
            ),
        }
        _notice = colorize(_fail_hints.get(_fail_net, "Failed to connect."), "red")
        safe_print(_notice)
        # The exit purge wipes the terminal (scrollback included), which took
        # this reason with it: on Termux only "Clean shutdown" was left and the
        # client seemed to close for no reason (owner report, 2026-10-24).
        # Nothing private was ever shown, so the purge repeats the reason.
        _b._exit_notice = _notice
        return 1

    client.start_auto_smp_monitor()

    _run_input_loop(client, _select)

    _restore_terminal()
    client.shutdown()
    return 0


def run():
    """`python otrv4+.py`: harden the process, then run the client."""
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except Exception:
        pass

    try:
        gc.freeze()
    except AttributeError:
        pass

    sys.setswitchinterval(0.05)

    if "PYTHONMALLOC" not in os.environ:
        print(
            colorize(
                "[HARDENING] For maximum security launch with:  "
                "PYTHONMALLOC=malloc python otrv4+.py",
                "yellow",
            )
        )

    def _purge_on_exit():
        """Last-chance scrollback purge.

        `shutdown()` already does this on the /quit path, but /quit is not
        the only way out: SIGINT during a blocking read, an unhandled
        exception, `sys.exit` from an argument error.  Whichever way the
        process leaves, the conversation should not be left rendered in the
        terminal for the next person to hold the handset.  Idempotent -- a
        second purge over empty panels does nothing.
        """
        client = getattr(__import__("builtins"), "_active_client", None)
        if client is not None:
            try:
                client._purge_scrollback("process exit", announce=False)
            except Exception:
                pass
        # Why the client is closing, said again after the wipe (which only
        # happens on a terminal; a pipe or log already has it once).
        notice = getattr(__import__("builtins"), "_exit_notice", None)
        if notice and sys.stdout.isatty():
            safe_print(notice)
        safe_print(colorize("\nClean shutdown", "green"))

    atexit.register(_purge_on_exit)

    main()
