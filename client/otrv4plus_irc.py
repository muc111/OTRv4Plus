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


def _fmt_duration(seconds: float) -> str:
    """Format seconds into human-readable string: 1d 2h 30m 15s"""
    s = int(seconds)
    if s < 0:
        return "0s"
    parts = []
    if s >= 86400:
        d, s = divmod(s, 86400)
        parts.append(f"{d }d")
    if s >= 3600:
        h, s = divmod(s, 3600)
        parts.append(f"{h }h")
    if s >= 60:
        m, s = divmod(s, 60)
        parts.append(f"{m }m")
    if s > 0 or not parts:
        parts.append(f"{s }s")
    return " ".join(parts)


class TwentySevenClubNick:
    """Generate unique IRC nicks from a large combinatorial pool.

    Combines adjectives with historical/cultural figure surnames to
    produce ~10,000+ unique nicks.  Each nick maps to a plausible
    real name for /whois display.

    Original 27 Club names are preserved as a subset for backward
    compatibility - existing users keep their nick identity.

    IRC nick constraints:
      - Max 30 characters (most servers allow 9-30)
      - No spaces, no leading #&: or digits
      - ASCII printable only
    """

    _LEGACY = [
        ("KurtCobain", "Kurt Cobain", "Nirvana"),
        ("AmyWinehouse", "Amy Winehouse", "Solo"),
        ("JimiHendrix", "Jimi Hendrix", "The Jimi Hendrix Experience"),
        ("JanisJoplin", "Janis Joplin", "Big Brother & The Holding Company"),
        ("JimMorrison", "Jim Morrison", "The Doors"),
        ("BrianJones", "Brian Jones", "The Rolling Stones"),
        ("RobertJohnson", "Robert Johnson", "Blues Legend"),
        ("AlanWilson", "Alan Wilson", "Canned Heat"),
        ("RonMcKernan", "Ron McKernan", "Grateful Dead"),
        ("PeteHam", "Pete Ham", "Badfinger"),
        ("RandyRhoads", "Randy Rhoads", "Ozzy Osbourne"),
        ("HillelSlovak", "Hillel Slovak", "Red Hot Chili Peppers"),
        ("AndrewWood", "Andrew Wood", "Mother Love Bone"),
        ("KristenPfaff", "Kristen Pfaff", "Hole"),
        ("RicheyEdwards", "Richey Edwards", "Manic Street Preachers"),
        ("DaveAlexander", "Dave Alexander", "The Stooges"),
        ("GaryThain", "Gary Thain", "Uriah Heep"),
        ("LesHarvey", "Les Harvey", "Stone the Crows"),
        ("ChrisBell", "Chris Bell", "Big Star"),
        ("JeremyWard", "Jeremy Ward", "The Mars Volta"),
    ]

    _ADJECTIVES = [
        "Silent",
        "Shadow",
        "Phantom",
        "Midnight",
        "Iron",
        "Crimson",
        "Golden",
        "Silver",
        "Dark",
        "Bright",
        "Swift",
        "Fierce",
        "Calm",
        "Wild",
        "Lone",
        "Bitter",
        "Hollow",
        "Frozen",
        "Burning",
        "Hidden",
        "Ancient",
        "Broken",
        "Fading",
        "Rising",
        "Fallen",
        "Distant",
        "Restless",
        "Wicked",
        "Noble",
        "Stray",
        "Drifting",
        "Echoing",
        "Veiled",
        "Stark",
        "Ashen",
        "Copper",
        "Jade",
        "Cobalt",
        "Ember",
        "Onyx",
        "Rustic",
        "Pale",
        "Dusky",
        "Misty",
        "Stormy",
        "Feral",
        "Glacial",
        "Lunar",
        "Solar",
        "Rogue",
        "Scarlet",
        "Azure",
        "Violet",
        "Ivory",
        "Obsidian",
        "Granite",
        "Cedar",
        "Birch",
        "Rowan",
        "Hazel",
        "Wraith",
        "Spectre",
        "Vagrant",
        "Nomad",
        "Hermit",
        "Cipher",
        "Zero",
        "Null",
        "Void",
        "Apex",
        "Primal",
        "Austere",
        "Cryptic",
        "Arcane",
        "Lucid",
        "Serene",
        "Turbid",
        "Waning",
        "Waxing",
        "Errant",
        "Sullen",
        "Muted",
        "Stark",
        "Gaunt",
        "Bleak",
        "Thorned",
        "Barbed",
        "Tempered",
        "Forged",
        "Annealed",
        "Quartz",
        "Basalt",
        "Slate",
        "Flint",
        "Ochre",
        "Boreal",
        "Tundra",
        "Steppe",
        "Taiga",
        "Mesa",
    ]

    _NOUNS = [
        "Wolf",
        "Hawk",
        "Raven",
        "Fox",
        "Lynx",
        "Bear",
        "Owl",
        "Crane",
        "Viper",
        "Falcon",
        "Heron",
        "Sparrow",
        "Condor",
        "Osprey",
        "Kestrel",
        "Jackal",
        "Panther",
        "Cobra",
        "Mantis",
        "Hornet",
        "Badger",
        "Otter",
        "Marten",
        "Wren",
        "Finch",
        "Forge",
        "Anvil",
        "Blade",
        "Shield",
        "Arrow",
        "Spire",
        "Bastion",
        "Citadel",
        "Tower",
        "Gate",
        "Storm",
        "Thunder",
        "Frost",
        "Blaze",
        "Ember",
        "Tide",
        "Current",
        "Drift",
        "Torrent",
        "Gale",
        "Root",
        "Thorn",
        "Branch",
        "Stone",
        "Ridge",
        "Peak",
        "Crest",
        "Vale",
        "Glen",
        "Cairn",
        "Dusk",
        "Dawn",
        "Shade",
        "Gloom",
        "Haze",
        "Reef",
        "Shoal",
        "Fjord",
        "Gorge",
        "Ravine",
        "Cipher",
        "Signal",
        "Beacon",
        "Pulse",
        "Vector",
        "Prism",
        "Shard",
        "Relic",
        "Glyph",
        "Rune",
        "Wick",
        "Tallow",
        "Flint",
        "Spark",
        "Cinder",
        "Quarry",
        "Ledge",
        "Scree",
        "Moraine",
        "Talus",
        "Styx",
        "Lethe",
        "Acheron",
        "Eris",
        "Nyx",
        "Odin",
        "Loki",
        "Fenrir",
        "Mimir",
        "Tyr",
        "Kappa",
        "Sigma",
        "Delta",
        "Theta",
        "Omega",
        "Vertex",
        "Node",
        "Orbit",
        "Zenith",
        "Nadir",
        "Mantle",
        "Cortex",
        "Nexus",
        "Vortex",
        "Matrix",
    ]

    _LOOKUP = {nick: (real, band) for nick, real, band in _LEGACY}

    @classmethod
    def generate(cls) -> str:
        """Generate a unique nick from the combinatorial pool.

        Format: AdjectiveNoun (e.g. SilentWolf, CrimsonForge)
        Pool: ~100 × 120 = ~12,000 unique combinations.
        Collision probability with <100 concurrent users: negligible.
        """
        adj = secrets.choice(cls._ADJECTIVES)
        noun = secrets.choice(cls._NOUNS)
        nick = adj + noun

        if len(nick) > 30:
            nick = nick[:30]
        return nick

    @classmethod
    def real_name(cls, nick: str) -> str:
        """Return the realname (gecos) advertised at USER registration.

        Legacy 27 Club nicks keep their real identity; generated nicks get a
        plausible format.  Every form ends with VERSION, because this string
        is the client's only identification channel over IRC -- CTCP VERSION
        is refused -- and /names reads it back out of RPL_WHOREPLY.

        Before v10.14.0 the 27 Club branch returned "... - 27 Club" with no
        version, and a NickServ nick advertised the bare nick, so two whole
        classes of OTRv4+ user were undetectable by their own peers.  A
        detection mechanism the client does not consistently feed is not a
        detection mechanism.
        """
        base = nick.rstrip("_0123456789")
        if base in cls._LOOKUP:
            real, band = cls._LOOKUP[base]
            return f"{real } ({band }) - 27 Club - {VERSION }"
        return f"{nick } - {VERSION }"

    @classmethod
    def is_member(cls, nick: str) -> bool:
        base = nick.rstrip("_0123456789")
        return base in cls._LOOKUP


class OTRv4IRCClient:
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

    def _detect_network(self) -> str:
        """Auto-detect clearnet / Tor / I2P from the configured server hostname."""
        return NetworkConstants.detect(self.server)

    def setup_proxy(self, net_type: str = None) -> str:
        """Configure PySocks SOCKS5 proxy based on network type.

        *net_type* is one of NetworkConstants.NET_* constants.
        If omitted, auto-detects from self.server.

        Returns the net_type that was applied (useful for logging).
        """
        if net_type is None:
            net_type = self._detect_network()

        if net_type == NetworkConstants.NET_I2P:
            host, port = self.config.i2p_proxy
            if not _probe_socks5(host, port, timeout=2.0):
                raise ConnectionError(
                    f"I2P SOCKS5 proxy not reachable on {host }:{port }.\n"
                    "  → Ensure i2pd is running (SOCKS5 port 4447)."
                )
            socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, host, port, rdns=True)
            socket.socket = socks.socksocket
            self.add_message(
                "system",
                colorize(
                    f"🧅 I2P SOCKS5 proxy: {_sanitise (str (host ),64 )}:{port }", "dark_cyan"
                ),
            )
            self.debug("proxy set", {"type": "i2p", "host": host, "port": port})

        elif net_type == NetworkConstants.NET_TOR:
            host, _cfg_port = self.config.tor_proxy

            _tor_candidates = [_cfg_port]
            for _alt in (9050, 9150):
                if _alt not in _tor_candidates:
                    _tor_candidates.append(_alt)
            port = None
            for _p in _tor_candidates:
                if _probe_socks5(host, _p, timeout=2.0):
                    port = _p
                    break
            if port is None:
                tried = ", ".join(str(p) for p in _tor_candidates)
                raise ConnectionError(
                    f"Tor SOCKS5 proxy not reachable on {host } "
                    f"(tried ports: {tried }).\n"
                    "  → Start Orbot and tap 'Start' before connecting."
                )

            self.config.tor_proxy = (host, port)
            socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, host, port, rdns=True)
            socket.socket = socks.socksocket
            self.add_message(
                "system", colorize(f"🧅 Tor SOCKS5 proxy: {host }:{port }", "dark_magenta")
            )
            self.debug("proxy set", {"type": "tor", "host": host, "port": port})

        else:
            socks.setdefaultproxy()
            socket.socket = socks.socksocket
            self.add_message("system", colorize("🌐 Clearnet (no proxy)", "grey"))
            self.debug("proxy set", {"type": "clearnet"})

        return net_type

    def connect(self) -> bool:
        """Open TCP connection, auto-routing via I2P / Tor / clearnet.

        Network type is detected from the server hostname:
          *.i2p    → I2P SAM bridge (preferred) or SOCKS5 (fallback)
          *.onion  → Tor SOCKS5 on 127.0.0.1:9050 (no TLS - tunnel encrypted)
          anything else → clearnet TCP with TLS on port 6697

        For I2P, SAM is strongly preferred over SOCKS5: SAM creates a
        unique transient destination per session, while SOCKS5 shares
        one destination across all connections (trivially correlatable).

        IRCv3 CAP negotiation is performed before NICK/USER registration.
        """
        try:
            net_type = NetworkConstants.detect(self.server)

            if net_type == NetworkConstants.NET_TOR:
                _onion_host = self.server
                if _onion_host.lower().endswith(".onion"):
                    _onion_label = _onion_host[:-6]
                    if len(_onion_label) == 16:
                        pass
                    elif len(_onion_label) != 56:
                        raise ValueError(
                            f"Invalid .onion address - label is {len (_onion_label )} chars, "
                            f"expected 56 (v3) or 16 (v2).\n"
                            f"  Got:     {_onion_host }\n"
                            f"  Hint: v3 onion addresses look like "
                            f"<56-char-base32>.onion"
                        )

            timeout_map = {
                NetworkConstants.NET_CLEARNET: NetworkConstants.TIMEOUT_CLEARNET,
                NetworkConstants.NET_TOR: NetworkConstants.TIMEOUT_TOR,
                NetworkConstants.NET_I2P: NetworkConstants.TIMEOUT_I2P,
            }
            timeout = timeout_map.get(net_type, NetworkConstants.TIMEOUT_I2P)

            use_tls = self.config.use_tls
            port = self.config.port

            if net_type == NetworkConstants.NET_CLEARNET:
                if port == 0:
                    port = IRCConstants.TLS_PORT

                if port == IRCConstants.PORT and not self.config.use_tls:

                    self.add_message(
                        "system",
                        colorize(
                            "⚠ Plaintext port 6667 - most networks now "
                            "require TLS on 6697. Use -p 6697 if reset.",
                            "yellow",
                        ),
                    )
                    use_tls = False
                else:
                    port = IRCConstants.TLS_PORT
                    use_tls = True
            else:
                use_tls = False
                if port == 0:
                    port = IRCConstants.PORT

            net_label = {
                NetworkConstants.NET_I2P: "I2P",
                NetworkConstants.NET_TOR: "Tor",
                NetworkConstants.NET_CLEARNET: "clearnet",
            }.get(net_type, net_type)

            sock = None
            self._sam_connection = None

            if net_type == NetworkConstants.NET_I2P:
                sock = self._sam_socket(net_type, port, timeout)

            if sock is None:
                sock = self._proxy_or_direct_socket(net_type, port, timeout, use_tls, net_label)

            if use_tls:
                import ssl as _ssl

                ctx = _ssl.create_default_context()
                sock = ctx.wrap_socket(sock, server_hostname=self.server)
                self.add_message("system", colorize("🔒 TLS handshake complete", "green"))

            sock.setblocking(True)
            sock.settimeout(1.0)

            self.sock = sock
            self.connected = True
            self.connected_at = time.time()
            self.running = True
            self.last_ping = time.time()
            self.auto_joined = False
            self.auth_complete = False
            self.nickserv_identified = False

            self._cap_negotiating = True
            self._cap_accepted: set = set()
            self._cap_end_sent = False
            self._sasl_in_progress = False

            self._recv_thread = threading.Thread(
                target=self._recv_loop, daemon=True, name="irc-recv"
            )
            self._recv_thread.start()

            self.send_raw("CAP LS 302")
            self.send_raw(f"NICK {self .nick }")
            self.send_raw(f"USER {self .nick } 0 * :{self .realname }")

            self.add_message("system", f"✅ Connected - nick: {colorize_username (self .nick )}")
            self.debug("handshake sent", {"caps": "LS 302"})
            return True

        except Exception as exc:
            self.add_message("system", "❌ Connection failed")
            self.debug("connect failed", {"error": str(exc)})
            self.connected = False
            return False

    def _sam_socket(self, net_type, port, timeout):
        """A socket through the I2P SAM bridge, or None to fall back to SOCKS."""
        sock = None
        sam_host, sam_port = self.config.i2p_sam
        if I2PSAMConnection.is_available(sam_host, sam_port):
            try:
                self.add_message(
                    "system",
                    f"Connecting to {colorize (self .server ,'cyan')} via "
                    f"{colorize ('SAM bridge','green')} (unique destination)…",
                )
                self.debug(
                    "connect",
                    {
                        "server": self.server,
                        "port": port,
                        "net": "i2p-sam",
                        "tls": False,
                        "timeout": timeout,
                    },
                )

                sam = I2PSAMConnection(sam_host, sam_port)
                sock = sam.connect(self.server, port)
                self._sam_connection = sam

                self.add_message(
                    "system",
                    colorize("🧅 I2P SAM: unique destination per session", "green"),
                )
            except Exception as e:
                self.debug("sam_failed")
                self.add_message(
                    "system",
                    colorize(f"SAM failed ({e }), falling back to SOCKS5…", "yellow"),
                )
                sock = None
        return sock

    def _proxy_or_direct_socket(self, net_type, port, timeout, use_tls, net_label):
        """A socket through Tor or I2P SOCKS, or straight to a clearnet server.
        Raises on failure; connect() reports it."""
        sock = None

        if net_type == NetworkConstants.NET_TOR:

            _tor_SOCKS5_ERRORS = {
                0x01: "general SOCKS server failure (Tor may not be bootstrapped)",
                0x02: "connection not allowed by ruleset",
                0x03: "network unreachable",
                0x04: "host unreachable (hidden service may be down)",
                0x05: "connection refused by destination",
                0x06: "TTL expired",
                0x07: "command not supported",
                0x08: "address type not supported",
            }

            proxy_host, _cfg_port = self.config.tor_proxy
            _candidates = [_cfg_port]
            for _alt in (9050, 9150):
                if _alt not in _candidates:
                    _candidates.append(_alt)

            proxy_port = None
            for _p in _candidates:
                if _probe_socks5(proxy_host, _p, timeout=2.0):
                    proxy_port = _p
                    break

            if proxy_port is None:
                tried = ", ".join(str(p) for p in _candidates)
                raise ConnectionError(
                    f"Tor SOCKS5 not reachable on {proxy_host } "
                    f"(tried ports: {tried })\n"
                    "  → Is tor running?  Check: systemctl status tor"
                )

            self.config.tor_proxy = (proxy_host, proxy_port)

            self.add_message(
                "system",
                f"Connecting to {colorize (self .server ,'cyan')}:{port } via "
                f"{colorize ('Tor SOCKS5','dark_magenta')} ({proxy_host }:{proxy_port })…",
            )

            def _recvexact(s, n):
                """Read exactly n bytes, raising on short read."""
                buf = b""
                while len(buf) < n:
                    chunk = s.recv(n - len(buf))
                    if not chunk:
                        raise ConnectionError(
                            f"SOCKS5: connection closed (got {len (buf )}/{n } bytes)"
                        )
                    buf += chunk
                return buf

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(float(timeout))
            sock.connect((proxy_host, proxy_port))

            sock.send(b"\x05\x01\x00")
            auth_resp = _recvexact(sock, 2)
            if auth_resp[0] != 5:
                raise ConnectionError(
                    f"SOCKS5 greeting: unexpected version byte {auth_resp [0 ]:#04x}"
                )
            if auth_resp[1] == 0xFF:
                raise ConnectionError(
                    "SOCKS5 greeting: proxy requires authentication "
                    "(add 'SocksPolicy accept 127.0.0.1' to torrc)"
                )
            if auth_resp[1] != 0x00:
                raise ConnectionError(
                    f"SOCKS5 greeting: unsupported auth method {auth_resp [1 ]:#04x}"
                )

            domain = self.server.encode("ascii")
            req = (
                b"\x05\x01\x00\x03"
                + bytes([len(domain)])
                + domain
                + struct.pack("!H", port)
            )
            sock.send(req)

            hdr = _recvexact(sock, 4)
            if hdr[0] != 5:
                raise ConnectionError(
                    f"SOCKS5 response: unexpected version byte {hdr [0 ]:#04x}"
                )
            rep = hdr[1]
            if rep != 0x00:
                err_desc = _tor_SOCKS5_ERRORS.get(rep, f"unknown error code {rep :#04x}")
                raise ConnectionError(f"SOCKS5 CONNECT rejected: {err_desc }")

            atyp = hdr[3]
            if atyp == 0x01:
                _recvexact(sock, 4)
            elif atyp == 0x03:
                _recvexact(sock, ord(_recvexact(sock, 1)))
            elif atyp == 0x04:
                _recvexact(sock, 16)
            _recvexact(sock, 2)

            self.add_message("system", colorize("🧅 Tor circuit established", "green"))

        else:

            net_type_actual = self.setup_proxy(net_type)
            tls_label = " TLS" if use_tls else ""
            self.add_message(
                "system",
                f"Connecting to {colorize (self .server ,'cyan')}:{port }"
                f" ({colorize (net_label +tls_label ,'bold_cyan')}, up to {timeout }s)…",
            )
            self.debug(
                "connect",
                {
                    "server": self.server,
                    "port": port,
                    "net": net_type,
                    "tls": use_tls,
                    "timeout": timeout,
                },
            )

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(float(timeout))
            sock.connect((self.server, port))
        return sock

    def _recv_loop(self):
        """
        Background thread: read raw bytes from the socket, split on CRLF,
        dispatch each complete line to handle_message().
        Runs until self.running is False or the socket closes.

        All errors are caught and surfaced to the user panel - the thread
        never silently terminates without telling the user what happened.
        """
        buf = ""
        self.debug("recv loop started")
        while self.running and not self.shutdown_flag:
            try:
                chunk = self.sock.recv(4096)
                if not chunk:
                    if self.running:
                        self.add_message(
                            "system",
                            colorize(
                                "⚠ Server closed the connection. " "Reconnecting automatically…",
                                "yellow",
                            ),
                        )
                        self._report_disconnect_context()
                        self._try_reconnect()
                        return
                    self.connected = False
                    self.running = False
                    break
                buf += chunk.decode("utf-8", errors="replace")
                if len(buf) > 65536:
                    self.debug("recv buffer overflow - truncating")
                    buf = buf[-32768:]
                while "\r\n" in buf:
                    line, buf = buf.split("\r\n", 1)
                    line = line.strip()
                    if len(line) > 8192:
                        self.debug("oversized IRC line dropped")
                        continue
                    if line:
                        try:
                            self.handle_message(line)
                        except Exception as exc:
                            self.debug("handle_message error")
            except socket.timeout:
                now = time.time()
                if now - self.last_ping > 600:
                    self.add_message(
                        "system", colorize("⚠ Ping timeout. Reconnecting automatically…", "yellow")
                    )
                    self._try_reconnect()
                    return
                if hasattr(self, "_msg_rate") and len(self._msg_rate) > 500:
                    self._msg_rate.clear()
                _has_otr = hasattr(self, "session_manager") and bool(
                    self.session_manager.list_encrypted_sessions()
                )
                _irc_ping_interval = 90 if _has_otr else 150
                if not hasattr(self, "_last_irc_ping"):
                    self._last_irc_ping = now
                if now - self._last_irc_ping >= _irc_ping_interval:
                    try:
                        self.send_raw(f"PING :{self .server }")
                        self._last_irc_ping = now
                    except Exception:
                        pass

                try:
                    hb_interval = getattr(self.config, "heartbeat_interval", 60)
                    if hasattr(self, "session_manager") and hasattr(self, "_last_otr_sent"):
                        for peer, sess in list(self.session_manager.sessions.items()):
                            if (
                                getattr(sess, "session_state", None) is not None
                                and sess.session_state.name == "ENCRYPTED"
                            ):
                                peer_last = self._last_otr_sent.get(peer, 0)
                                if now - peer_last >= hb_interval:
                                    try:
                                        hb = sess.encrypt_with_tlvs("", [])
                                        if hb:
                                            self.send_otr_message(peer, hb)
                                            self._last_otr_sent[peer] = now
                                    except Exception:
                                        pass
                except Exception:
                    pass
                continue
            except OSError as exc:
                if self.running:

                    _uptime = time.time() - getattr(self, "connected_at", 0)
                    _is_clearnet_plain = (
                        NetworkConstants.detect(self.server) == NetworkConstants.NET_CLEARNET
                        and not self.config.use_tls
                        and self.config.port in (IRCConstants.PORT, 0)
                    )
                    if _uptime < 3.0 and _is_clearnet_plain and "104" in str(exc):
                        self.add_message(
                            "system",
                            colorize(
                                "⚠ Server reset plaintext connection - "
                                "auto-upgrading to TLS on port 6697…",
                                "yellow",
                            ),
                        )
                        self.config.use_tls = True
                        self.config.port = IRCConstants.TLS_PORT
                    else:
                        self.add_message(
                            "system",
                            colorize(
                                f"⚠ Connection lost ({exc }). " "Reconnecting automatically…",
                                "yellow",
                            ),
                        )
                    self._try_reconnect()
                    return
                self.connected = False
                self.running = False
                break
            except Exception as exc:
                self.debug("recv_loop unexpected error")
                try:
                    self.add_message(
                        "system",
                        colorize(f"⚠ Network error (recovered): {str (exc )[:80 ]}", "yellow"),
                    )
                except Exception:
                    pass

        self.debug("recv loop ended")

    def _try_reconnect(self):
        """Close the old socket, reset all OTR/session state, and reconnect."""
        self._reconnecting = True
        self._rejoin_channels = list(self.channels.keys()) if self.channels else []

        self.connected = False
        self.running = False
        try:
            if self.sock:
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
        self.auto_joined = False
        self.auth_complete = False
        self.nickserv_identified = False

        self._preserved = self._preserve_otr_across_reconnect()

        # Everything on screen belongs to the connection that just ended.
        # Purge before the backoff, not after: if the user is watching the
        # countdown, they should not be reading the dead session while they
        # wait for the next one.
        self._purge_scrollback("connection lost", announce=False,
                               wipe_terminal=False)

        self.connection_attempts += 1
        backoff = self._reconnect_backoff(self.connection_attempts)
        self.add_message(
            "system", f"🔄 Reconnecting in {backoff}s (attempt {self.connection_attempts})…"
        )

        for _ in range(backoff * 10):
            if getattr(self, "shutdown_flag", False):
                self._rejoin_channels = []
                return
            time.sleep(0.1)
        if self.connection_attempts <= self.max_connection_attempts:
            if self.connect():

                self._reconnecting = False
            else:
                self._reconnecting = False
        else:
            self._reconnecting = False
            self.add_message("system", colorize("❌ Max reconnect attempts reached.", "red"))

    #: Nicks already told about a missing session, so a peer cannot fill the
    #: panel by repeating an undecryptable message.
    _NO_SESSION_WARNED_MAX = 64

    def _other_session_nicks(self, exclude: str):
        """Nicks we hold OTR sessions with, other than *exclude*."""
        try:
            return sorted(p for p in self.session_manager.sessions
                          if isinstance(p, str) and p != exclude)
        except Exception:
            return []

    def _warn_nick_change_keeps_session(self, old_nick: str, new_nick: str):
        """The server says old_nick is now new_nick and we hold their session.

        The session is NOT moved, and that is the point rather than a
        limitation.  A nick is a name the server hands out and takes back; the
        keys belong to the DAKE that produced them.  Following a rename would
        mean encrypting to whoever holds a name now, which is the one mistake
        that turns a preserved session into a leak.  So the keys stay put and
        the user is told, in the tab where the conversation was.
        """
        old = _sanitise(old_nick, 64)
        new = _sanitise(new_nick, 64)
        sec = None
        try:
            sec = self.session_manager.get_security_level(old_nick)
        except Exception:
            pass
        self.add_message(old_nick, colorize(
            "🔴 OTR SESSION NOT CARRIED OVER", "red"), sec)
        self.add_message(old_nick, colorize(
            "   %s is now %s. The encrypted session stays with %s: keys "
            "follow the handshake that made them, not a name the server has "
            "just reassigned." % (old, new, old), "yellow"), sec)
        self.add_message(old_nick, colorize(
            "   Run  /otr %s  to start a new session with them, then compare "
            "the fingerprint against the one pinned for %s before you trust "
            "it." % (new, old), "cyan"), sec)
        self.add_message(old_nick, colorize(
            "   /endotr %s  clears the old session when you no longer want "
            "it." % old, "dim"), sec)

    def _warn_no_session_for_nick(self, sender: str):
        """An encrypted message arrived from a nick we have no session with.

        Until v10.24.1 this was a bare `return`: the message was dropped and
        nothing was said, so a peer who reconnected under a new nick simply
        went quiet.  With sessions now surviving a reconnect that silence is
        more likely, not less, and it looks identical to the peer having
        nothing to say.

        What this must NOT do is claim the new nick is the old peer.  Nothing
        here proves that -- the message did not decrypt, so there is no
        evidence of who sent it.  It reports what is true (no session for this
        nick, sessions held for these others) and leaves the identification
        to the user and to the fingerprint.
        """
        warned = getattr(self, "_no_session_warned", None)
        if warned is None:
            warned = self._no_session_warned = set()
        if sender in warned:
            return
        if len(warned) >= self._NO_SESSION_WARNED_MAX:
            return
        warned.add(sender)

        nick = _sanitise(sender, 64)
        self.add_message(sender, colorize(
            "🔴 OTR SESSION NOT FOUND", "red"))
        self.add_message(sender, colorize(
            "   An encrypted message arrived from %s, but there is no "
            "session with that nick. It cannot be read and was dropped."
            % nick, "yellow"))
        others = self._other_session_nicks(sender)
        if others:
            self.add_message(sender, colorize(
                "   You do have encrypted session(s) with: %s."
                % _sanitise(", ".join(others), 256), "yellow"))
            self.add_message(sender, colorize(
                "   If this is one of them on a new nick, their keys stayed "
                "with the old one — nothing is moved automatically, because "
                "an IRC nick is not an identity.", "dim"))
        self.add_message(sender, colorize(
            "   Run  /otr %s  to start a new session, and check the "
            "fingerprint against one you already trust." % nick, "cyan"))

    def _dake_stage(self, peer: str, stage: int, outcome: str,
                    detail: str = "", note: str = "") -> None:
        """One handshake stage, said once, after it has actually happened.

        The old output was a running commentary -- "DAKE1 -> sent - waiting
        for response...", "DAKE2 <- received from X", "DAKE3 -> sent to X" --
        interleaved with fragment progress bars, and on a handset it was hard
        to tell which step you were on or whether it had worked.

        The header and the verdict are emitted together, from one call, and
        that is deliberate rather than tidy: there is no way to print
        `OK` for a stage whose operation has not returned, because there is
        no code path that prints the header on its own.  A stage that fails
        prints its own failure against its own number.

        `detail` is for debug mode only -- fragment counts are invaluable
        when something breaks and noise when it does not, which is the same
        split the XMPP client makes with `_dbg`.

        Nothing here takes key material, a transcript, or a secret: the
        arguments are a peer name, a small integer, and fixed strings.
        """
        sec = None
        try:
            sec = self.session_manager.get_security_level(peer)
        except Exception:
            pass
        self.add_message(peer, colorize("🔐 DAKE %d" % stage, "cyan"), sec)
        if outcome == "ok":
            self.add_message(peer, colorize("🟢 OK", "green"), sec)
            if note:
                self.add_message(peer, colorize("   %s" % note, "dim"), sec)
        else:
            self.add_message(peer, colorize(
                "🔴 FAILED — %s" % _sanitise(str(outcome), 120), "red"), sec)
        if detail:
            self.debug("dake stage", {"stage": stage, "detail": detail})

    def _dake_ready(self, peer: str) -> None:
        """The line the whole handshake exists to reach."""
        sec = None
        try:
            sec = self.session_manager.get_security_level(peer)
        except Exception:
            pass
        self.add_message(peer, colorize("🟢 OTR SESSION READY", "bold_green"),
                         sec)

    def _preserve_otr_across_reconnect(self) -> dict:
        """Carry the cryptographic session across a transport interruption.

        An I2P SAM tunnel dying is not a security boundary.  Until v10.24.0
        this method's predecessor treated it as one: it called
        `ratchet.zeroize()` on every session, wiped the root and chain keys,
        and emptied `session_manager.sessions`.  A tunnel blip therefore
        destroyed every encrypted conversation on the client, and the only
        way back was `/quit` and a full restart -- reported from a handset
        after exactly that.

        The XMPP client has never done this.  `_on_disconnected` there drops
        trades and presence, rebuilds the tunnel, reconnects the stream, and
        leaves `self.otr.sessions` untouched; the double ratchet is a
        property of the two peers, not of the socket that carried it.  This
        brings IRC to the same behaviour.

        WHAT IS KEPT
        ------------
        The session objects, and with them the ratchet, the root and chain
        keys, the message counters, the pinned fingerprint and the SMP state.
        The identity key and client profile were never touched here and still
        are not, so the fingerprint a peer pinned stays the fingerprint they
        see -- a reconnect must not look like a new person.

        WHAT IS DROPPED, AND WHY EACH ONE HAS TO BE
        -------------------------------------------
        *Inbound fragment buffers.*  A half-reassembled OTR message whose
        remaining fragments were on the socket that just died can never
        complete, and keeping it means the next connection's fragments get
        appended to the previous connection's prefix.  That is a corrupt
        message at best.  They are per-connection by nature.

        *An armed passphrase prompt.*  Leaving `_secret_request` set across a
        reconnect would make the user's next line a passphrase for a session
        whose transport just vanished, and leave the input mask on over their
        ordinary chat.  INV-06 is about who may arm that prompt; this is the
        other half -- it must not outlive the thing it was armed for.

        *A pending consent question.*  Same reason: the y/n belongs to a
        request that arrived on the old connection.

        WHAT IS NOT REPLAYED
        --------------------
        Nothing.  No data message, no fragment, no SMP message is re-sent.
        OTRv4 replay protection is not something to work around, and a
        message the peer already processed must not arrive twice.  Messages
        lost in the drop are lost; the ratchet's skipped-key handling covers
        the gap for what follows.

        Returns a summary for `_report_preserved_sessions` to print once the
        transport is back, so the user is told what survived rather than
        having to guess from the padlock.
        """
        summary = {"sessions": [], "smp_in_flight": [], "disarmed": False}

        try:
            for peer, sess in list(self.session_manager.sessions.items()):
                try:
                    level = self.session_manager.get_security_level(peer)
                except Exception:
                    level = UIConstants.SecurityLevel.ENCRYPTED
                summary["sessions"].append((peer, level))
                # A verification part-way through: its next message was on
                # the connection that died, so the run may be stranded.  Say
                # so rather than leaving the user waiting on a step that will
                # never arrive.
                try:
                    phase = sess.rust_smp.get_phase() if sess.rust_smp else ""
                except Exception:
                    phase = ""
                if phase.startswith("AWAITING_MSG") or phase == "SECRET_REQUIRED":
                    summary["smp_in_flight"].append(peer)
        except Exception:
            self.debug("preserve: could not enumerate sessions")

        # The prompt, before anything else can consume a line.  Looked up
        # rather than called directly: the guided flow lives on
        # EnhancedOTRv4IRCClient and this method is on the base, and a base
        # class that assumes a subclass method exists is the shape of the
        # v10.23.0 dispatcher bug.  A base-only client has no prompt to
        # disarm, and that is a correct answer rather than an AttributeError.
        try:
            disarm = getattr(self, "_disarm_secret_prompt", None)
            if (getattr(self, "_secret_request", None) is not None
                    and callable(disarm)):
                disarm()
                summary["disarmed"] = True
        except Exception:
            self.debug("preserve: could not disarm the secret prompt")
        try:
            self._pending_action = None
            if hasattr(self, "_smp_consent_shown"):
                self._smp_consent_shown = None
        except Exception:
            pass

        # Partial reassembly belongs to the connection that carried it.
        try:
            self.fragment_buffers.clear()
        except Exception:
            self.debug("preserve: could not clear fragment buffers")

        # Panels for peers with no session go back to plaintext; a panel whose
        # session survived keeps its badge, because the session did.
        try:
            live = {peer for peer, _ in summary["sessions"]}
            for panel in self.panel_manager.panels.values():
                if panel.name in live:
                    continue
                panel.security_level = UIConstants.SecurityLevel.PLAINTEXT
                panel.secure_session = False
                panel.type = (
                    "channel"
                    if panel.name.startswith("#")
                    else "system" if panel.name == "system" else "private"
                )
        except Exception:
            pass

        return summary

    def _report_preserved_sessions(self) -> None:
        """Say what came through the reconnect.  Called once, after JOIN.

        The point is that the user can tell the difference between "your
        encrypted session is still there" and "the padlock is stale".  A
        badge that survived a transport drop with no explanation is a claim
        the user has no way to check.
        """
        summary = getattr(self, "_preserved", None)
        if not summary:
            return
        self._preserved = None

        def sec(peer):
            """The panel badge, via the subclass helper when there is one."""
            helper = getattr(self, "_panel_sec", None)
            if callable(helper):
                try:
                    return helper(peer)
                except Exception:
                    pass
            panel = self.panel_manager.panels.get(peer)
            return getattr(panel, "security_level", None)
        peers = summary.get("sessions") or []
        if not peers:
            return
        self.add_message("system", colorize(
            "🔐 %d OTR session(s) kept through the reconnect — identity keys "
            "and pinned fingerprints unchanged." % len(peers), "green"))
        for peer, _level in peers:
            self.add_message(peer, colorize(
                "🔐 Transport reconnected. This session continues — same "
                "keys, same fingerprint, nothing re-negotiated.", "green"),
                sec(peer))
            self.add_message(peer, colorize(
                "🔐 Anything sent while the connection was down did not "
                "arrive and is not re-sent.", "dim"), sec(peer))
        for peer in summary.get("smp_in_flight") or []:
            self.add_message(peer, colorize(
                "🔐 A verification was part-way through when the connection "
                "dropped. If it does not finish, run  /smp abort  and then "
                "/smp  to start again.", "yellow"), sec(peer))
        if summary.get("disarmed"):
            self.add_message("system", colorize(
                "🔐 The passphrase prompt was cancelled by the disconnect. "
                "Nothing was stored or sent.", "yellow"))

    #: Floor and ceiling for the reconnect backoff, in seconds.
    #:
    #: The old schedule started at 5s and doubled.  Five seconds is shorter
    #: than any server's ping timeout, so the reconnect arrived while our
    #: previous session was still registered and holding the nick: the server
    #: answered 433, the client renamed itself, and the user watched
    #: AngryMouse become BrokenNexus become HollowNexus over three drops --
    #: with the old session's messages still on screen under each new name.
    #:
    #: Thirty seconds is the floor because it clears the common
    #: ping-timeout window on the networks this client is used on.  It is not
    #: a guarantee (a server with a 120s timeout will still collide once),
    #: which is why the nick reclaim below exists as well: the backoff makes
    #: the collision unlikely, the reclaim makes it survivable.
    RECONNECT_BACKOFF_MIN = 30
    RECONNECT_BACKOFF_MAX = 120

    @classmethod
    def _reconnect_backoff(cls, attempt: int) -> int:
        """Seconds to wait before reconnect attempt `attempt` (1-based).

        Linear, not exponential: 30, 60, 90, 120, 120, ...  Exponential
        growth past two minutes is not useful here -- a server that is still
        refusing after two minutes is down, and the user is better served by
        a steady retry they can predict than by a wait that doubles into the
        tens of minutes.
        """
        return min(cls.RECONNECT_BACKOFF_MAX,
                   cls.RECONNECT_BACKOFF_MIN * max(1, attempt))

    #: How long to leave a ghosted session to time out before asking for the
    #: nick back, and how many times to ask.  Four attempts spans two minutes,
    #: which covers every ping timeout this client has been run against; past
    #: that the nick is someone else's and retrying is just noise.
    NICK_RECLAIM_DELAY = 30
    NICK_RECLAIM_ATTEMPTS = 4

    def _on_nick_collision(self) -> None:
        """Handle 433/436 without permanently giving up our nick.

        The old behaviour was to generate a fresh random nick and keep it.
        That is correct exactly once -- during registration you must present
        *some* free nick or the server will not let you finish -- and wrong
        every time after, because the usual cause of a collision here is our
        own previous session still ghosted on the server.  Renaming
        permanently meant one dropped connection cost the user their
        identity, and three dropped connections produced three identities,
        none of which their peers recognised.

        So: take a temporary nick only if we are not registered yet, and
        either way schedule a reclaim of the original once the ghost has had
        time to expire.  If someone else genuinely holds the nick, the
        reclaim attempts fail quietly and we keep what we have.
        """
        original = getattr(self, "_original_nick", None) or self.nick
        self._original_nick = original

        if self.auth_complete:
            # Already registered: this is a failed reclaim, not a failed
            # login.  Keep the nick we have and try again later.
            self._schedule_nick_reclaim()
            return

        temporary = TwentySevenClubNick.generate()
        if temporary == self.nick:
            temporary = self.nick + str(secrets.randbelow(100))
        self.nick = temporary
        self.realname = TwentySevenClubNick.real_name(self.nick)
        self.send(f"NICK {self.nick}")
        self.add_message(
            "system",
            f"Nick collision → {colorize_username(self.nick)} "
            f"(will try to reclaim {colorize_username(original)})",
        )
        self._schedule_nick_reclaim()

    def _schedule_nick_reclaim(self) -> None:
        """Ask for `_original_nick` back after the ghost has had time to die."""
        original = getattr(self, "_original_nick", None)
        if not original or original == self.nick:
            self._nick_reclaim_tries = 0
            return
        tries = getattr(self, "_nick_reclaim_tries", 0)
        if tries >= self.NICK_RECLAIM_ATTEMPTS:
            return
        self._nick_reclaim_tries = tries + 1

        def _reclaim():
            if getattr(self, "shutdown_flag", False) or not self.connected:
                return
            if self.nick == original:
                self._nick_reclaim_tries = 0
                return
            self.send(f"NICK {original}")

        timer = threading.Timer(self.NICK_RECLAIM_DELAY, _reclaim)
        timer.daemon = True
        timer.start()
        self._nick_reclaim_timer = timer

    def send_raw(self, message: str) -> bool:
        """Send a raw IRC line (adds CRLF, enforces 510-byte limit).

        Truncation here means OTRMessageFragmenter failed to split the message
        properly - it is logged as a bug, never silently discarded.
        """
        message = message.replace("\r", "").replace("\n", "")
        if len(message) > 510:
            self.debug(
                f"BUG: send_raw truncated {len (message )}→510 bytes. "
                "Fragmentation should have prevented this.",
                {"head": message[:80]},
            )
            message = message[:510]
        try:
            with self._sock_lock:
                if self.sock:
                    self.sock.sendall(f"{message }\r\n".encode("utf-8"))
                    self.logger.network_message("OUT", "SERVER", "RAW", len(message))
                    self.debug("send")
                    return True
        except Exception as exc:
            self.debug("send_raw failed")
            self.running = False
        return False

    def send(self, message: str) -> bool:
        """Send only if connected."""
        return self.send_raw(message) if self.running else False

    # ── outbound line pacing ────────────────────────────────────────────────
    #
    # A 12 KiB SMP2 is 48 IRC lines.  How fast those may go out is set by the
    # server, not by us, and getting it wrong costs a disconnect mid-handshake
    # -- which on I2P means several more minutes to rebuild.  So the model
    # here is the one mainstream ircds actually implement rather than a guess:
    # a leaky bucket where each line costs a fixed penalty, the allowance
    # refills at one second per second, and exceeding the cap is what earns
    # "Excess Flood".
    #
    # The clearnet path has always used it (cost 2.0, cap 10.0).  The I2P path
    # did not: it slept 6s after every second fragment, an average of 3.15s a
    # line, which is roughly half the rate the same model permits.  Measured
    # against a real handshake on irc.postman.i2p that pacing accounted for
    # about ten minutes of a seventeen-minute verification -- pure sleeping,
    # not latency and not computation.
    #
    # The presets below are the tuning surface.  NORMAL is the standard ircd
    # penalty; SAFE is the old I2P behaviour, kept because it is the one rate
    # known to survive; FAST is for a server that tolerates more, and is
    # opt-in because nobody here can prove which servers do.
    #: name -> (cost per line, starting allowance, cap, minimum gap)
    PACE_PRESETS = {
        # allowance 2x cost: the behaviour being reproduced sent two lines
        # 0.30s apart and then paused 6s, so two lines have to clear before
        # the penalty bites.  With a one-line allowance a two-fragment message
        # took 3.15s where the old code took 0.30 -- slower, in the name of
        # reproducing it.
        "safe":   (3.15, 6.30, 10.0, 0.30),
        "normal": (2.00, 4.00, 10.0, 0.05),
        "fast":   (1.00, 4.00, 10.0, 0.05),
        "turbo":  (0.50, 4.00, 10.0, 0.05),
    }
    #: What `/fragrate` accepts.  "auto" is not a fixed rate so it has no
    #: entry above; it picks one of the others per message.
    PACE_CHOICES = ("safe", "normal", "fast", "turbo", "auto")
    #: Back to "safe" in v10.25.1.  v10.25.0 made "normal" the default on the
    #: arithmetic -- it is the penalty mainstream ircds implement, and the old
    #: rate was paying double for no recorded reason.  The first real run at
    #: it ended with the server closing the connection 55 seconds after a
    #: 17-fragment DAKE1, and one observed disconnect is enough: a lost
    #: handshake costs minutes on I2P, and the conservative rate is the one
    #: the user already had working.
    #:
    #: What that run did NOT establish is that the pacing caused it.  No
    #: ERROR line arrived -- a flood kill on most ircds says "Closing Link:
    #: ... (Excess Flood)" first -- the disconnected side was idle at the
    #: time rather than sending, and an I2P tunnel dropping looks identical
    #: from here.  So this is a retreat to the known-good value, not a
    #: diagnosis.  `/fragrate` and the disconnect report added alongside it
    #: are how the question gets answered with evidence instead.
    DEFAULT_PACE = "safe"

    # ── the fitted model of irc.postman.i2p ─────────────────────────────────
    #
    # Three observations, all on 2026-09-05, all at 403-406 byte fragments:
    #
    #   24 lines at 0.54 s/line  survived   (a DAKE2 at turbo)
    #   34 lines at 0.97 s/line  KILLED     (an SMP2 at fast, "Excess Flood")
    #   24 lines at 2.00 s/line  survived   (a full DAKE at normal)
    #
    # Fit a leaky bucket -- the server charges PENALTY seconds per line, the
    # allowance refills one second per second, and the connection dies when
    # accumulated debt passes BUDGET.  Debt after n lines at interval i is
    # n * (PENALTY - i).  The survived case needs BUDGET >= 35 and the killed
    # case needs BUDGET < 35, which pins both parameters at PENALTY = 2.0 and
    # BUDGET ~= 35 exactly.  A penalty of 1.5 is inconsistent with the pair;
    # 2.5 fits too but is less parsimonious and would only make this more
    # conservative.
    #
    # THE USEFUL CONSEQUENCE.  At a cost equal to or above the penalty, debt
    # never accumulates and the rate is safe at any message length -- which is
    # why `normal` carried a whole DAKE and `safe` two whole verifications.
    # Below it, debt grows per line and the safe length is BUDGET divided by
    # the shortfall.  So the limit is not a rate, it is a rate AND a length,
    # and a message short enough can go faster than a sustained rate ever
    # could.
    #
    # Fragment counts, measured: DAKE1 16, DAKE2 24, DAKE3 19, SMP1 23,
    # SMP2 47, SMP3 47, SMP4 20.  Only SMP2 and SMP3 are long enough to
    # exhaust the budget at `fast`.
    #
    # Two data points and a straight line through them is not a proof, so
    # BUDGET here is 20% under what was measured, and `auto` is opt-in.
    #: Refitted a second time in v10.26.2, and this is the last time the
    #: number moves on guesswork.  A fifth observation -- a 47-fragment SMP2
    #: at `normal`, killed -- makes a penalty of 2.0 arithmetically
    #: impossible: `normal` costs exactly 2.0, so at that penalty its debt
    #: after the burst is zero and no length could ever be refused, yet one
    #: was.  Solving the five observations together needs a penalty of at
    #: least 2.75, and 3.0 fits with room.
    #:
    #: THE CONSEQUENCE IS THE WHOLE ANSWER.  At 3.0, `safe` (3.15 s/line) is
    #: the ONLY preset whose debt per line is negative, and therefore the only
    #: one safe at the lengths this protocol sends.  That is not a coincidence
    #: discovered here -- it is why `safe` has completed two full
    #: verifications on this server while `normal`, `fast` and `turbo` have
    #: been killed with "Excess Flood" between them four times.
    #:
    #: Three refits now, every one of them correcting in the unsafe
    #: direction.  The model is a heuristic for an UNKNOWN server, not a
    #: licence to go faster on this one.
    FLOOD_LINE_PENALTY = 3.0
    #: The burst is charged at the FULL penalty, not the shortfall -- see
    #: `_flood_debt`.  Lines covered by the allowance go out back to back at
    #: essentially zero interval, so the server bills each of them in full
    #: while the client waits almost nothing.  Getting that backwards in
    #: v10.26.0 under-counted every message by (allowance/cost) * cost.
    #:
    #: At penalty 3.0 the five observations put the real budget between 38 and
    #: 42.  This is 15: low enough that `auto` chooses `safe` for every
    #: message this protocol sends, which is the answer the wire has given
    #: four times.  It is deliberately not the fitted value -- fitting it
    #: closely is what produced two releases that got a handset killed.
    FLOOD_DEBT_BUDGET = 15.0
    #: Presets `auto` may choose between, fastest first.  `turbo` is excluded
    #: deliberately: it is the preset for finding a ceiling by hitting it,
    #: which is not a thing to do automatically.
    AUTO_CANDIDATES = ("fast", "normal", "safe")

    def _auto_preset_for(self, fragments: int) -> str:
        """Fastest preset that can carry *fragments* lines within the budget.

        The message length is the input because the server's limit is a debt,
        not a rate.

        WHAT THIS NOW ANSWERS, AND IT IS NOT WHAT IT WAS BUILT FOR.  With the
        burst charged correctly and the budget refitted, nothing below the
        penalty can carry a message of the size this protocol sends: at
        `fast` the limit is eleven lines and the shortest OTR message is
        sixteen.  So `auto` returns `normal` for every real message on a
        server like this one, and the honest reading is that `normal` -- the
        rate whose debt is exactly zero -- is the floor, not that `auto` is
        clever.  It is kept because the arithmetic is the useful part: on a
        more tolerant server the same rule would pick `fast`, and on a
        stricter one it will pick `safe` without anybody having to notice.

        Assumes the debt has drained between messages.  It refills a second a
        second and an OTRv4 handshake waits tens of seconds for each reply, so
        that holds for the protocol as it runs; it would not hold for a client
        that sent two long messages back to back, and nothing here does.
        """
        for name in self.AUTO_CANDIDATES:
            cost, allowance, _cap, _floor = self.PACE_PRESETS[name]
            shortfall = self.FLOOD_LINE_PENALTY - cost
            if shortfall <= 0:
                return name          # never accumulates: safe at any length
            if self._flood_debt(fragments, cost, allowance) <= \
                    self.FLOOD_DEBT_BUDGET:
                return name
        return self.AUTO_CANDIDATES[-1]

    def _flood_debt(self, fragments: int, cost: float,
                    allowance: float) -> float:
        """Seconds of penalty *fragments* lines would owe the server.

        The burst is the part that was wrong before.  Lines covered by the
        allowance go out back to back, so the server charges each of them the
        full penalty while we wait almost no time at all; only the lines after
        it are paced, and those owe just the shortfall.  Treating the burst
        like a paced line under-counted the debt by (allowance/cost) * cost --
        eight seconds at `fast`, against a budget of fifteen.
        """
        if cost <= 0:
            return float("inf")
        burst = min(max(0, fragments), int(allowance // cost))
        paced = max(0, fragments - burst)
        return (burst * self.FLOOD_LINE_PENALTY
                + paced * max(0.0, self.FLOOD_LINE_PENALTY - cost))

    #: What a server says when it has had enough.  Matching any of these drops
    #: the session to SAFE for the rest of the run: a disconnect mid-DAKE is
    #: far more expensive than a slow one, so evidence of throttling is acted
    #: on immediately and never automatically undone.
    FLOOD_MARKERS = ("excess flood", "flooding", "flood detected",
                     "max sendq", "sendq exceeded", "too many lines",
                     "throttl")

    class _Pacer:
        """Leaky-bucket line pacer.  One per send, seeded from the client.

        Kept as an object rather than inline arithmetic so the pacing can be
        tested without a socket -- `wait()` is pure except for the sleep, and
        the tests substitute a clock.
        """

        def __init__(self, cost, allowance, cap, floor, sleep=time.sleep,
                     clock=time.monotonic):
            self.cost = cost
            self.bucket = allowance
            self.cap = cap
            self.floor = floor
            self._sleep = sleep
            self._clock = clock
            self._prev = clock()
            self.slept = 0.0

        def wait(self):
            now = self._clock()
            self.bucket = min(self.cap, self.bucket + (now - self._prev))
            self._prev = now
            delay = 0.0
            if self.bucket < self.cost:
                delay = self.cost - self.bucket
            if self.floor > delay:
                delay = self.floor
            if delay > 0:
                self._sleep(delay)
                self.slept += delay
                self.bucket = min(self.cap, self.bucket + delay)
                self._prev = self._clock()
            self.bucket -= self.cost

    def _report_disconnect_context(self) -> None:
        """Say what was happening when the connection went, not just that it did.

        A dropped connection on I2P has several causes that look identical
        from here -- a flood kill, a ping timeout, the SAM tunnel dying, the
        server restarting -- and "Server closed the connection" distinguishes
        none of them.  A session was lost mid-DAKE with the pacing newly
        changed, and there was no way to tell from the log whether the pacing
        had anything to do with it.  These four facts separate the cases:

          * an ERROR line, if one arrived.  Most ircds send "Closing Link:
            ... (Excess Flood)" before a flood kill, so its ABSENCE is
            evidence too, and worth printing as such.
          * seconds since the last PING/PONG.  A large number points at a
            ping timeout, which on this client means the receive thread was
            blocked -- see _send_worker.
          * seconds since our last outbound OTR message, and how many
            fragments it was.  A drop during or just after a burst points at
            the send rate; a drop while idle does not.
          * the pacing preset in force, because that is the setting under
            suspicion and it should not have to be remembered separately.

        Prints nothing sensitive: counts, seconds, a preset name, and a
        server-supplied string that is sanitised.
        """
        now = time.time()
        lines = []
        err = getattr(self, "_last_server_error", None)
        if err and now - err[1] < 120:
            lines.append("   Server said: %s" % _sanitise(err[0], 200))
        else:
            lines.append("   No ERROR line from the server — a flood kill "
                         "usually sends one first.")
        try:
            since_ping = now - float(getattr(self, "last_ping", 0) or 0)
            if since_ping < 86400:
                lines.append("   %.0fs since the last message from the server."
                             % since_ping)
        except Exception:
            pass
        # `_last_otr_sent` records only SUCCESSFUL sends, and the send that
        # earns a flood kill is by definition the one that failed -- so on a
        # handset this reported "29s since our last OTR message (23
        # fragments)" where the 29s came from the DAKE3 that landed and the 23
        # from the SMP1 that was cut off at fragment 19.  Two different
        # messages in one sentence, in a report whose whole job is to say what
        # was happening.  `_last_send_started` is written when a send begins,
        # so the pair belong to each other.
        last_sent = float(getattr(self, "_last_send_started", 0.0) or 0.0)
        if not last_sent:
            try:
                for _peer, _ts in getattr(self, "_last_otr_sent", {}).items():
                    last_sent = max(last_sent, _ts)
            except Exception:
                pass
        if last_sent:
            lines.append("   %.0fs since our last OTR message (%d fragments)."
                         % (now - last_sent,
                            getattr(self, "_last_fragment_count", 0)))
        else:
            lines.append("   No OTR message sent on this connection.")
        # The preset the LAST SEND used, not the live one.  On the path this
        # report exists for, _note_possible_flood has already dropped the
        # live value to 'safe' by the time the socket closes, so reading it
        # here reported the retreat rather than the cause.
        sent_at = getattr(self, "_last_send_preset", None)
        now_at = self._pace_name()
        if sent_at and sent_at != now_at:
            lines.append("   Fragment pacing was '%s' for that send, and is "
                         "'%s' now. /fragrate to change it."
                         % (sent_at, now_at))
        else:
            lines.append("   Fragment pacing was '%s'. /fragrate to change it."
                         % (sent_at or now_at))
        for line in lines:
            self.add_message("system", colorize(line, "dim"))

    def _describe_auto(self) -> None:
        """Show where `auto`'s cut-off falls, in fragments and in messages.

        A rule nobody can see the boundary of is a rule nobody can check, and
        this one is fitted from two observations rather than derived.
        """
        cut = {}
        for name in self.AUTO_CANDIDATES:
            shortfall = self.FLOOD_LINE_PENALTY - self.PACE_PRESETS[name][0]
            if shortfall <= 0:
                cut[name] = None     # no limit
            else:
                cut[name] = int(self.FLOOD_DEBT_BUDGET // shortfall)
        parts = []
        for name in self.AUTO_CANDIDATES:
            limit = cut[name]
            parts.append("%s up to %d lines" % (name, limit) if limit
                         else "%s beyond that" % name)
        self.add_message("system", colorize(
            "   " + ", ".join(parts) + ".", "dim"))
        self.add_message("system", colorize(
            "   A DAKE message is 16-24 fragments and an SMP2/SMP3 is 47, so "
            "the handshake goes fast and the two big proofs do not.", "dim"))
        self.add_message("system", colorize(
            "   Fitted from two disconnects on irc.postman.i2p, with a 20% "
            "margin. Not proven — if it gets you killed, say so.", "yellow"))

    def _cmd_fragrate(self, arg: str) -> None:
        """`/fragrate` — show the pacing, or change it.

        The sweet spot for a given server cannot be derived; it has to be
        found. This shows what the last multi-fragment send actually achieved
        so a rate can be raised, tried against a real handshake, and kept or
        reverted on evidence rather than on feel.

        In memory only, like everything else the IRC client holds (INV-10).
        A new session starts at the default.
        """
        arg = (arg or "").strip().lower()
        if arg and arg not in self.PACE_CHOICES:
            self.add_message("system", colorize(
                "Usage: /fragrate [%s]" % " | ".join(self.PACE_CHOICES), "red"))
            return
        if arg:
            self._pace_preset = arg
            if arg == "auto":
                self.add_message("system", colorize(
                    "📶 Fragment pacing: auto — the rate is chosen per "
                    "message from its length.", "cyan"))
                self._describe_auto()
                return
            cost, _a, _c, floor = self.PACE_PRESETS[arg]
            self.add_message("system", colorize(
                "📶 Fragment pacing: %s — about %.2f lines/sec sustained."
                % (arg, 1.0 / cost), "cyan"))
            if arg in ("fast", "turbo"):
                self.add_message("system", colorize(
                    "   Above the standard ircd penalty. If the server "
                    "disconnects you mid-handshake, this is why — it drops "
                    "back to 'safe' on its own if the server says so.",
                    "yellow"))
            return

        name = self._pace_name()
        if name == "auto":
            self.add_message("system", colorize(
                "📶 Fragment pacing: auto — chosen per message from its "
                "length.", "cyan"))
            self._describe_auto()
        else:
            cost, allowance, cap, floor = self.PACE_PRESETS[name]
            self.add_message("system", colorize(
                "📶 Fragment pacing: %s — %.2f s/line sustained, burst "
                "%.0f lines." % (name, cost, allowance / cost), "cyan"))
        stats = getattr(self, "_last_send_stats", None)
        if stats:
            self.add_message("system", colorize(
                "   Last multi-fragment send: %d fragments in %.1fs "
                "(%.2f lines/sec)."
                % (stats["fragments"], stats["elapsed"],
                   stats["lines_per_sec"]), "dim"))
        else:
            self.add_message("system", colorize(
                "   No multi-fragment send yet this session.", "dim"))
        size = self._fragment_size(
            "peer", NetworkConstants.detect(getattr(self, "server", "")))
        if getattr(self, "_own_prefix", None):
            self.add_message("system", colorize(
                "   Fragment size %d bytes (from the server-reported prefix)."
                % size, "dim"))
        else:
            self.add_message("system", colorize(
                "   Fragment size %d bytes (prefix not seen yet — join a "
                "channel and it is measured)." % size, "dim"))
        self.add_message("system", colorize(
            "   /fragrate %s" % " | ".join(self.PACE_PRESETS), "dim"))

    def _pace_name(self) -> str:
        return getattr(self, "_pace_preset", None) or self.DEFAULT_PACE

    def _pacer(self, net: str, fragments: Optional[int] = None):
        """A pacer for one message.

        Clearnet keeps the standard penalty regardless of the preset: the
        preset exists to tune an overlay network where the round trip already
        dwarfs the pacing, and letting it loosen a clearnet connection would
        be tuning the wrong thing.

        `fragments` is how long this particular message is, and only `auto`
        uses it -- see `_auto_preset_for`.  Optional so every existing caller
        and test keeps working; without it `auto` falls back to the rate that
        is safe at any length rather than guessing.

        The chosen preset is recorded on the returned pacer as `.preset`, so
        the disconnect report and `/fragrate` can name what a send actually
        used rather than what the setting was called.
        """
        name = "normal"
        if net == NetworkConstants.NET_CLEARNET:
            cost, allowance, cap, floor = self.PACE_PRESETS["normal"]
        elif net == NetworkConstants.NET_TOR:
            cost, allowance, cap, floor = self.PACE_PRESETS["normal"]
            floor = 0.20
        else:
            name = self._pace_name()
            if name == "auto":
                name = (self._auto_preset_for(fragments)
                        if fragments else self.AUTO_CANDIDATES[-1])
            cost, allowance, cap, floor = self.PACE_PRESETS[name]
        pacer = self._Pacer(cost, allowance, cap, floor)
        pacer.preset = name
        return pacer

    #: How many PACED lines a sample needs on top of the burst before its
    #: lines/sec means anything.  Three is enough to separate the sustained
    #: rate from the allowance.
    RATE_SAMPLE_PACED_LINES = 3

    def _rate_sample_min(self) -> int:
        """Fewest fragments that make a meaningful rate sample, for the preset
        currently in force.

        Not a constant, because the burst is not.  `safe` and `normal` clear
        two lines before the penalty bites, `fast` four and `turbo` eight --
        so a five-fragment sample is three paced lines on `safe` and pure
        allowance on `turbo`, where it would report 8 lines/sec for a preset
        whose sustained rate is 2.  A fixed threshold is right for exactly one
        of the four presets.
        """
        try:
            cost, allowance, _cap, _floor = self.PACE_PRESETS[self._pace_name()]
            burst = int(allowance // cost)
        except Exception:
            burst = 2
        return burst + self.RATE_SAMPLE_PACED_LINES

    def _record_send_rate(self, fragments: int, elapsed: float) -> None:
        """Remember what the last multi-fragment send actually achieved.

        The point of measuring is that the sweet spot cannot be derived, only
        found: `/fragrate` reports this so a rate can be raised, tried on a
        real handshake, and kept or reverted on evidence.

        Short sends are ignored, and that is the difference between a useful
        number and a misleading one.  A heartbeat is two fragments, both of
        which come out of the burst allowance without waiting, so it measures
        3.3 lines/sec on a preset whose sustained rate is 0.32.  Seen on a
        handset: a 60-second heartbeat overwrote the measurement of a
        23-fragment SMP1 with exactly that, at the moment the number was
        being used to decide whether to go faster.
        """
        if fragments < self._rate_sample_min() or elapsed <= 0:
            return
        self._last_send_stats = {
            "fragments": fragments,
            "elapsed": elapsed,
            "lines_per_sec": fragments / elapsed,
            "preset": self._pace_name(),
        }
        self.debug("send rate", {"frags": fragments,
                                 "secs": round(elapsed, 1),
                                 "lines_per_sec": round(fragments / elapsed, 2),
                                 "preset": self._pace_name()})

    def _note_peer_flood(self, peer: str, reason: str) -> bool:
        """Back off after a PEER is disconnected for flooding.

        Distinct from `_note_possible_flood`, which reads an ERROR addressed
        to us, because the wording has to be different: nothing has gone wrong
        here yet, and the user needs to know why their working session just
        slowed down.
        """
        blob = (reason or "").lower()
        if not any(marker in blob for marker in self.FLOOD_MARKERS):
            return False
        already_safe = self._pace_name() == "safe"
        self._pace_preset = "safe"
        if already_safe:
            return True
        self.add_message("system", colorize(
            "⚠ %s was disconnected by the server for flooding, at the same "
            "fragment rate this client is using." % _sanitise(peer, 64),
            "yellow"))
        self.add_message("system", colorize(
            "   Pacing dropped to 'safe' here too — the next long message "
            "from this end would have been the one to go.", "yellow"))
        self.add_message("system", colorize(
            "   /fragrate shows it. It is not raised again automatically.",
            "dim"))
        return True

    def _note_possible_flood(self, reason: str) -> bool:
        """Drop to SAFE if *reason* looks like the server complaining.

        Never raises the rate again on its own.  A server that threw us off
        once will do it again, and an automatic recovery would rediscover the
        limit the expensive way, mid-handshake.
        """
        blob = (reason or "").lower()
        if not any(marker in blob for marker in self.FLOOD_MARKERS):
            return False
        if self._pace_name() == "safe":
            return True
        self._pace_preset = "safe"
        self.add_message("system", colorize(
            "⚠ The server complained about the send rate — fragment pacing "
            "dropped to 'safe' for this session.", "yellow"))
        self.add_message("system", colorize(
            "   /fragrate  shows the current setting. It is not raised again "
            "automatically.", "dim"))
        return True

    #: Bounds on the derived fragment size.
    #:
    #: FRAG_SIZE_MAX is a ceiling, and it is a real one: it leaves room for a
    #: server that rewrites our prefix after we measured it (a vhost applied
    #: post-JOIN) without the line overflowing.
    #:
    #: FRAG_SIZE_FLOOR is a sanity bound, NOT a "known good" value.  It used
    #: to be 380 applied with max(), which is a bug rather than a safety net:
    #: when the computed limit came out BELOW 380 -- a long nick and a long
    #: target on top of a b32 host cloak -- the floor overrode it and the line
    #: went out at 520 bytes, to be truncated by the server along with the
    #: fragment's terminating "." and the message with it.  A floor may only
    #: ever be a fallback for not knowing, never an override for knowing.
    FRAG_SIZE_FLOOR = 64
    FRAG_SIZE_MAX = 440
    #: Retained under the old name because tests and docs refer to it: the
    #: value this client used for every I2P fragment before the size was
    #: derived.  Nothing computes with it any more.
    FRAG_SIZE_MIN = 380
    #: Slack kept below the 512-byte line limit.
    FRAG_SAFETY_MARGIN = 8
    #: Worst-case user@host to assume before the server has told us ours.
    #: An IRC host is at most 63 characters and a user at most 10, so this
    #: over-estimates rather than truncates.
    FRAG_ASSUMED_USERHOST = 10 + 1 + 63

    def _fragment_size(self, target: str, net: str) -> int:
        """How many characters of fragment fit in one IRC line to *target*.

        The binding limit is not the line we send, it is the one the
        RECIPIENT sees: `:nick!user@host PRIVMSG target :<fragment>\r\n` must
        be at most 512 bytes, and the prefix is added by the server after we
        hand the line over.

        This was a fixed 380 for every I2P fragment.  Two things were wrong
        with that.  It was too small in the common case -- on a server that
        hands out a short host cloak it wasted about a tenth of every line,
        which is a tenth of the fragments and a tenth of the handshake -- and
        it was too large in the uncommon one: a thirty-character nick sending
        to a thirty-character target over a b32 cloak produces a 520-byte
        line, and the server truncates it.

        So it is computed, from the prefix the server echoed back with our own
        JOIN when we have it, and from our nick plus a worst-case user@host
        when we do not.  Both are bounded above by FRAG_SIZE_MAX and below
        only by a sanity floor.
        """
        if net != NetworkConstants.NET_I2P:
            return UIConstants.OTR_FRAGMENT_SIZE
        if not target:
            return self.FRAG_SIZE_MIN
        try:
            prefix = getattr(self, "_own_prefix", None)
            # A bare nick under-counts the overhead by the whole user@host
            # the server adds, so it is not a prefix for this purpose.
            if not prefix or "!" not in prefix or "@" not in prefix:
                nick = getattr(self, "nick", "") or ""
                prefix_len = len(nick) + 1 + self.FRAG_ASSUMED_USERHOST
            else:
                prefix_len = len(prefix)
            overhead = (1 + prefix_len + len(" PRIVMSG ") + len(target)
                        + len(" :") + 2 + self.FRAG_SAFETY_MARGIN)
            size = 512 - overhead
        except Exception:
            return self.FRAG_SIZE_MIN
        # Ceiling, then sanity floor.  The floor is deliberately far below any
        # plausible computed value: if it ever binds, the arithmetic above is
        # wrong and a small fragment is the safe way to be wrong.
        return max(self.FRAG_SIZE_FLOOR, min(self.FRAG_SIZE_MAX, size))

    def send_otr_message(self, target: str, otr_message: str) -> bool:
        """Fragment OTR message if needed and send each part.

        Looks up the session's instance tags so multi-fragment messages use the
        spec-compliant ``?OTRv4|stag|rtag|k|n|data.`` wire format (§4.7).
        Tracks the send time for the OTRv4 §4.7.1 heartbeat mechanism.
        """
        sender_tag = 0
        receiver_tag = 0
        try:
            sess = self.session_manager.get_session(target)
            if sess is not None:
                sender_tag = getattr(sess, "_sender_tag", 0) or 0
                receiver_tag = getattr(sess, "_receiver_tag", 0) or 0
        except Exception:
            pass

        _net = NetworkConstants.detect(getattr(self, "server", ""))
        _frag_sz = self._fragment_size(target, _net)
        fragments = self.otr_fragmenter.fragment(
            otr_message,
            sender_tag=sender_tag,
            receiver_tag=receiver_tag,
            max_line=_frag_sz,
        )
        # Recorded for the handshake display: the normal UI says "DAKE 1 / OK"
        # and debug mode adds the fragment count.  Kept as an attribute rather
        # than returned so no caller's signature changes.
        self._last_fragment_count = len(fragments)
        _pace = self._pacer(_net, len(fragments))
        # The preset THIS send is going out at, recorded before anything can
        # change it.  Taken from the pacer rather than from `_pace_name()`, so
        # that under `auto` it names the rate actually chosen for this message
        # instead of the word "auto".  _report_disconnect_context used to read the live value,
        # which meant that on the one path where the answer matters most --
        # the server sends ERROR, _note_possible_flood drops the rate to
        # 'safe', the socket then closes -- it reported the rate we had just
        # retreated to instead of the one that earned the kill.  A handset
        # sending 46 fragments at 'fast' was told "Fragment pacing was
        # 'safe'", which is the opposite of the fact the report exists for.
        self._last_send_preset = getattr(_pace, "preset", self._pace_name())
        # Wall clock, paired with _last_fragment_count above: the disconnect
        # report needs the time and the size of the SAME message, including
        # when that message is the one that never finished.
        self._last_send_started = time.time()
        _started = time.monotonic()
        ok = True
        for i, frag in enumerate(fragments):
            if len(fragments) > 1:
                _pace.wait()
            if len(fragments) > 1:
                try:
                    _tb = "█" * (i + 1) + "░" * (len(fragments) - i - 1)
                    _set_prompt(
                        f"\x1b[36m↑ TX {target } [{i +1 }/{len (fragments )}] {_tb }\x1b[0m "
                    )
                except Exception:
                    pass
            if not self.send(f"PRIVMSG {target } :{frag }"):
                ok = False
                if len(fragments) > 1:
                    self.add_message(
                        target if target in self.panel_manager.panels else "system",
                        colorize(
                            f"⚠ Fragment send failed at {i +1 }/{len (fragments )} - /otr {target } to retry",
                            "yellow",
                        ),
                    )
                break
        if ok:
            self._last_otr_sent[target] = time.time()
        if len(fragments) > 1:
            self._record_send_rate(len(fragments), time.monotonic() - _started)
        if len(fragments) > 1:
            try:
                if self._prompt_refresh_cb:
                    self._prompt_refresh_cb()
            except Exception:
                pass
        return ok

    def parse_irc_message(self, line: str):
        """Parse IRC protocol line → (prefix, command, params, trailing).

        Handles IRCv3 message tags: @tag=value;tag2 :prefix COMMAND ...
        Tags are stripped - the server-time tag is extracted if present
        but not yet used (available for future timestamp display).
        """
        prefix = None
        trailing = None
        _msg_tags = {}
        if line.startswith("@"):
            tags_str, line = line.split(" ", 1)
            for _t in tags_str[1:].split(";"):
                _k, _v = _t.split("=", 1) if "=" in _t else (_t, "")
                _msg_tags[_k] = _v

        if line.startswith(":"):
            parts = line[1:].split(" ", 1)
            prefix = parts[0]
            line = parts[1] if len(parts) > 1 else ""
        if " :" in line:
            params_str, trailing = line.split(" :", 1)
            params = params_str.strip().split()
        else:
            params = line.split()
        command = params[0] if params else None
        params = params[1:] if params else []
        return prefix, command, params, trailing, _msg_tags

    def _handle_cap(self, params: List[str], trailing: Optional[str]) -> None:
        """Handle CAP LS / ACK / NAK replies from the server."""
        if len(params) < 2:
            return
        sub = params[1].upper()

        if sub == "LS":

            avail = (trailing or "").split()

            wanted = [c for c in IRCConstants.IRCV3_CAPS if c in avail]
            if wanted:
                self.send_raw(f"CAP REQ :{' '.join (wanted )}")
                self.debug("cap_ls", {"available": avail, "requesting": wanted})
            else:
                self._finish_cap_negotiation()

        elif sub == "ACK":

            accepted = (trailing or "").split()
            self._cap_accepted.update(accepted)
            self.add_message("system", colorize(f"IRCv3: {', '.join (accepted )}", "dim"))
            self.debug("cap_ack", {"accepted": accepted})

            if (
                "sasl" in self._cap_accepted
                and getattr(self.config, "sasl_user", None)
                and getattr(self.config, "sasl_pass", None)
            ):
                self._sasl_in_progress = True
                self.send_raw("AUTHENTICATE PLAIN")
                self.add_message("system", colorize("🔑 SASL PLAIN authentication…", "cyan"))
            else:

                self._finish_cap_negotiation()

        elif sub == "NAK":

            self.debug("cap_nak", {"rejected": (trailing or "").split()})
            self._finish_cap_negotiation()

    def _handle_authenticate(self, trailing: Optional[str]) -> None:
        """Handle AUTHENTICATE + from server - send SASL PLAIN credentials."""
        if trailing == "+":
            user = self.config.sasl_user or self.nick
            _pw = self.config.sasl_pass or ""

            import base64 as _b64_sasl

            _plain_ba = bytearray(f"\x00{user }\x00{_pw }".encode("utf-8"))
            token = _b64_sasl.b64encode(bytes(_plain_ba)).decode("ascii")
            _secure_wipe(_plain_ba)
            del _plain_ba
            self.send_raw(f"AUTHENTICATE {token }")

            self.config.sasl_pass = None
            _pw = None
            del _pw
            self.debug("sasl_auth", {"user": user})

    def _finish_cap_negotiation(self) -> None:
        """End CAP negotiation - let the server complete registration.
        Guarded so CAP END is sent at most once per connection even if called
        from multiple paths (LS empty, ACK no-SASL, NAK, timeout).
        """
        if getattr(self, "_cap_end_sent", False):
            return
        if getattr(self, "_cap_negotiating", True):
            self._cap_negotiating = False
            self._cap_end_sent = True
            self.send_raw("CAP END")
            self.debug("cap_end", {"accepted": list(getattr(self, "_cap_accepted", set()))})

    def handle_message(self, line: str):
        """Dispatch one IRC line to the appropriate handler."""
        try:
            prefix, command, params, trailing, _tags = self.parse_irc_message(line)
            self.logger.network_message("IN", prefix or "SERVER", command or "?", len(line))
            self.debug(
                "recv", {"cmd": command, "params": params[:3], "trail": (trailing or "")[:120]}
            )

            if command and command.isdigit():
                self.handle_numeric_reply(int(command), params, trailing)
                return

            if command == "ERROR":
                # The last thing a server says before closing the link, and
                # the only place it names the reason.  Read for a flood
                # complaint before the socket goes: it is the evidence that
                # the send rate was too high, and it arrives exactly once.
                _why = trailing or " ".join(params)
                self._last_server_error = (_why, time.time())
                self._note_possible_flood(_why)
                self.add_message("system", colorize(
                    "⚠ Server: %s" % _sanitise(_why, 256), "red"))
                return

            if command == "PING":
                target = trailing or (params[0] if params else "server")
                self.send(f"PONG :{target }")
                self.last_ping = time.time()
                return
            if command == "PONG":
                self.last_ping = time.time()
                return

            if command == "CAP":
                self._handle_cap(params, trailing)
                return

            if command == "AUTHENTICATE":
                self._handle_authenticate(trailing)
                return

            sender = prefix.split("!")[0] if prefix and "!" in prefix else (prefix or "server")
            if sender in self.ignored_users:
                return

            for family in (self._on_chat, self._on_membership, self._on_identity):
                if family(command, sender, prefix, params, trailing, _tags):
                    return

        except Exception as exc:
            self.debug("handle_message error")

    def _on_chat(self, command, sender, prefix, params, trailing, _tags):
        """PRIVMSG, TAGMSG and NOTICE. True if *command* was one of them."""
        if command == "PRIVMSG":
            target = params[0] if params else ""
            message = trailing or ""
            if self.is_ctcp_message(message) and "?OTRv4" not in message:
                return True
            if len(message) > 4096:
                self.debug("oversized PRIVMSG dropped")
                return True
            self.check_auto_reply(sender, target, message)
            if "?OTRv4" in message:
                self._dispatch_otr_fragment(sender, message)
            else:
                _now = time.time()
                if not hasattr(self, "_msg_rate"):
                    self._msg_rate: dict = {}
                _bucket = self._msg_rate.get(sender, (0, 0.0))
                _count, _window_start = _bucket
                if _now - _window_start > 10.4:
                    _count, _window_start = 0, _now
                _count += 1
                self._msg_rate[sender] = (_count, _window_start)
                if _count > 50:
                    self.debug(
                        f"plaintext flood from {sender } - dropping ({_count } msgs/10s)"
                    )
                else:
                    self._display_plaintext(sender, target, message)
            return True

        if command == "TAGMSG":
            _tv = _tags.get("+typing", "")
            _tgt = params[0] if params else ""
            if _tgt == self.nick and _tv in ("active", "paused", "done"):
                _pnl = self.panel_manager.panels.get(sender)
                if _pnl is not None:
                    if _tv in ("active", "paused"):
                        _tmsg = colorize(
                            (
                                f"✍ {sender } is typing…"
                                if _tv == "active"
                                else f"✍ {sender } paused…"
                            ),
                            "yellow",
                        )
                        _last = _pnl.history[-1]["message"] if _pnl.history else ""
                        if "✍" in _last:
                            _pnl.history[-1]["message"] = _tmsg
                        else:
                            self.add_message(sender, _tmsg)
                    elif _tv == "done":
                        if _pnl.history and "✍" in _pnl.history[-1]["message"]:
                            _pnl.history.pop()
            return True
        if command == "NOTICE":
            target = params[0] if params else ""
            message = trailing or ""
            sender_lower = sender.lower() if sender else ""
            if sender_lower == "nickserv":
                self.add_message(
                    "system",
                    colorize("NickServ", "bold_cyan")
                    + colorize(": ", "dim")
                    + colorize(_sanitise(message, 512), "white"),
                )
                msg_lower = message.lower()
                if (
                    ("you are now" in msg_lower and "identified" in msg_lower)
                    or "password accepted" in msg_lower
                    or "you are successfully identified" in msg_lower
                ):
                    self.nickserv_identified = True
                    self.add_message(
                        "system", colorize("✅ NickServ: identified successfully", "green")
                    )
                elif "registered" in msg_lower and (
                    "successfully" in msg_lower or "is now" in msg_lower
                ):
                    self.nickserv_identified = True
                    self.add_message(
                        "system", colorize("✅ NickServ: nick registered successfully", "green")
                    )
                elif (
                    "invalid" in msg_lower
                    or "denied" in msg_lower
                    or "incorrect" in msg_lower
                    or "wrong" in msg_lower
                ):
                    self.add_message(
                        "system", colorize("❌ NickServ: authentication failed", "red")
                    )
            elif sender_lower in ("chanserv", "memoserv", "operserv"):
                self.add_message(
                    "system",
                    colorize(_sanitise(sender, 64), "dim")
                    + colorize(": ", "dim")
                    + colorize(_sanitise(message, 512), "dim"),
                )
            else:
                if message and not message.startswith("***"):
                    self.add_message(
                        "system",
                        colorize(
                            f"[notice] {_sanitise (sender ,64 )}: {_sanitise (message ,512 )}",
                            "dim",
                        ),
                    )
            return True
        return False

    def _on_membership(self, command, sender, prefix, params, trailing, _tags):
        """JOIN, PART, QUIT and KICK. True if *command* was one of them."""
        if command == "JOIN":
            channel = trailing or (params[0] if params else "")
            if not channel or len(channel) > 64 or "\r" in channel or "\n" in channel:
                return True
            if sender == self.nick:
                # The server echoes our JOIN back with our full prefix.
                # That is the only place we learn it, and knowing it is
                # worth about a tenth of every fragment -- see
                # _fragment_size.  "!" and "@" both required: a bare nick
                # would under-count the overhead and truncate lines.
                if prefix and "!" in prefix and "@" in prefix:
                    self._own_prefix = prefix
                    self.debug("own prefix", {"len": len(prefix)})
                if channel not in self.panel_manager.panels:
                    self.panel_manager.add_panel(channel, "channel")
                self._switch_panel(channel)
                self.channels[channel] = {"users": set(), "topic": ""}
                self.add_message(
                    channel, colorize(f"✅ Joined {_sanitise (channel ,64 )}", "green")
                )
            else:
                if channel in self.channels:
                    self.channels[channel]["users"].add(sender)
            return True

        if command == "PART":
            channel = params[0] if params else ""
            reason = trailing or ""
            if sender == self.nick:
                self.add_message("system", f"Left {_sanitise (channel ,64 )}")
                self.channels.pop(channel, None)
                if channel in self.panel_manager.panels:
                    _was = self.panel_manager.active_panel == channel
                    del self.panel_manager.panels[channel]
                    if channel in self.panel_manager.panel_order:
                        self.panel_manager.panel_order.remove(channel)
                    if _was:
                        self._switch_panel("system")
                    elif getattr(self, "_tui_enabled", False) and self._screen:
                        self._screen.redraw_full()
                    self.panel_manager._render_ui()
            else:
                if channel in self.channels:
                    self.channels[channel]["users"].discard(sender)
            return True

        if command == "QUIT":
            reason = trailing or ""
            for ch, info in self.channels.items():
                if sender in info["users"]:
                    info["users"].discard(sender)
            # Someone else may take the nick; a stale entry would mark
            # them as an OTRv4+ client on no evidence at all.
            getattr(self, "_otrv4_users", {}).pop(sender, None)

            if self.session_manager.has_session(sender):
                self._on_peer_disconnected(sender, reason)
            return True

        if command == "KICK":
            channel = params[0] if params else ""
            kicked = params[1] if len(params) > 1 else ""
            reason = trailing or ""
            if kicked == self.nick:
                self.add_message(
                    "system",
                    f"❌ Kicked from {_sanitise (channel ,64 )}: {_sanitise (reason ,256 )}",
                )
                self.channels.pop(channel, None)
                if channel in self.panel_manager.panels:
                    was_active = self.panel_manager.active_panel == channel
                    del self.panel_manager.panels[channel]
                    if channel in self.panel_manager.panel_order:
                        self.panel_manager.panel_order.remove(channel)
                    if was_active:
                        self._switch_panel("system")
                    elif getattr(self, "_tui_enabled", False) and self._screen is not None:
                        self._screen.redraw_full()
                    self.panel_manager._render_ui()
            else:
                self.add_message(
                    channel,
                    f"⚡ {colorize_username (_sanitise (kicked ,64 ))} kicked: {_sanitise (reason ,256 )}",
                )
            return True
        return False

    def _on_identity(self, command, sender, prefix, params, trailing, _tags):
        """NICK, MODE and TOPIC. True if *command* was one of them."""
        if command == "NICK":
            new_nick = trailing or (params[0] if params else "")
            if not new_nick or len(new_nick) > 64 or "\r" in new_nick or "\n" in new_nick:
                return True
            for ch_info in self.channels.values():
                if sender in ch_info["users"]:
                    ch_info["users"].discard(sender)
                    ch_info["users"].add(new_nick)
            # The OTRv4+ map is keyed by nick, so a rename would
            # otherwise leave the marker on a nick nobody is using and
            # strip it from the person who still has the same client.
            _o = getattr(self, "_otrv4_users", None)
            if _o is not None and sender in _o:
                _o[new_nick] = _o.pop(sender)
            # A peer we are encrypted with just changed name.  The keys do
            # not follow, and the user has to be told rather than left
            # wondering why the new nick is a plaintext tab.
            if sender != self.nick:
                try:
                    if self.session_manager.has_session(sender):
                        self._warn_nick_change_keeps_session(sender, new_nick)
                        _w = getattr(self, "_no_session_warned", None)
                        if _w is not None:
                            _w.discard(new_nick)
                except Exception:
                    self.debug("nick-change session notice failed")
            if sender == self.nick:
                self.nick = new_nick
                self.add_message(
                    "system", f"Nick → {colorize_username (_sanitise (new_nick ,64 ))}"
                )
                if new_nick == getattr(self, "_original_nick", None):
                    # Reclaim succeeded: stop asking.
                    self._nick_reclaim_tries = 0
                    self.realname = TwentySevenClubNick.real_name(new_nick)
            return True

        if command == "MODE":
            ch = params[0] if params else ""
            if ch.startswith("#"):
                self.add_message(ch, f"Mode: {_sanitise (' '.join (params [1 :]),128 )}")
            return True

        if command == "TOPIC":
            ch = params[0] if params else ""
            topic = trailing or ""
            if ch in self.channels:
                self.channels[ch]["topic"] = topic
            self.add_message(ch, f"Topic: {_sanitise (topic ,390 )}")
            return True
        return False

    def _handle_unknown_command(self, command: str, params, trailing) -> None:
        """No-op handler for unrecognised IRC commands - avoids super() AttributeError."""
        pass

    def handle_numeric_reply(self, code: int, params: List[str], trailing: Optional[str]):
        """Handle IRC numeric reply codes: each family answers whether the
        code was one of its own; anything left goes to `_rpl_other`."""
        try:
            for family in (self._rpl_auth, self._rpl_motd, self._rpl_who,
                           self._rpl_channel, self._rpl_whois):
                if family(code, params, trailing):
                    return
            self._rpl_other(code, params, trailing)
        except Exception as exc:
            self.debug("numeric reply error")

    def _rpl_auth(self, code, params, trailing):
        """SASL, the welcome and NickServ, a nick in use."""
        if code in (900, 903):

            self.nickserv_identified = True
            self.add_message("system", colorize("✅ SASL authentication successful", "green"))
            if getattr(self, "_sasl_in_progress", False):
                self._sasl_in_progress = False
                self._finish_cap_negotiation()
            return True

        if code in (902, 904, 905, 906):

            self.add_message(
                "system", colorize(f"⚠ SASL authentication failed (code {code })", "yellow")
            )
            if getattr(self, "_sasl_in_progress", False):
                self._sasl_in_progress = False
                self._finish_cap_negotiation()
            return True

        if code == 1:
            self.auth_complete = True
            welcome_text = trailing or ""
            words = welcome_text.split()
            clean_words = []
            for w in words:
                if "!" in w or "@" in w:
                    break
                clean_words.append(w)
            clean = " ".join(clean_words) if clean_words else welcome_text
            self.add_message("system", colorize(f"✅ {clean }", "green"))
            self.debug("RPL_WELCOME")
            if self.config.nickserv_login and self.config.nickserv_pass:
                self.add_message("system", colorize("🔑 Identifying with NickServ…", "cyan"))
                _ns_pass = self.config.nickserv_pass
                self.send(f"PRIVMSG NickServ :IDENTIFY {_ns_pass }")
                _ns_pass_ba = bytearray(_ns_pass.encode("utf-8"))
                _secure_wipe(_ns_pass_ba)
                del _ns_pass, _ns_pass_ba
                self.config.nickserv_pass = None
            elif self.config.nickserv_register and self.config.nickserv_pass:
                self.add_message(
                    "system", colorize("📝 Registering nick with NickServ…", "cyan")
                )
                _ns_pass = self.config.nickserv_pass
                self.send(f"PRIVMSG NickServ :REGISTER {_ns_pass } no-email")
                _ns_pass_ba = bytearray(_ns_pass.encode("utf-8"))
                _secure_wipe(_ns_pass_ba)
                del _ns_pass, _ns_pass_ba
                self.config.nickserv_pass = None

            delay = (
                3.0 if (self.config.nickserv_login or self.config.nickserv_register) else 2.0
            )
            threading.Timer(delay, self.auto_join_channel).start()
            return True

        if code in (433, 436):
            self._on_nick_collision()
            return True
        return False

    def _rpl_motd(self, code, params, trailing):
        """The message of the day and the server's statistics lines."""
        if code == 375:
            self._motd_buf = []
            return True
        if code == 372:
            if not hasattr(self, "_motd_buf"):
                self._motd_buf = []
            if trailing:
                import re as _re_irc

                line = trailing.lstrip("- ").strip()
                line = _re_irc.sub(r"\x03(?:\d{1,2}(?:,\d{1,2})?)?", "", line)
                line = _re_irc.sub(r"[\x02\x0f\x16\x1d\x1f]", "", line).strip()
                if line:
                    self._motd_buf.append(line)
            return True
        if code == 376:
            buf = getattr(self, "_motd_buf", [])
            if buf:
                self.add_message(
                    "system", colorize("── MOTD ──────────────────────────────────", "dim")
                )

                import re as _re

                _SECTION_RE = _re.compile(r"^(?:\d+[.)]\s|/|https?://|\[|[A-Z]{3,}\s*:)")
                paragraphs = []
                current = []
                for frag in buf:
                    is_new = (
                        not current
                        or _SECTION_RE.match(frag)
                        or (
                            len(frag) > 30
                            and frag[0].isupper()
                            and not current[-1].endswith(",")
                        )
                    )
                    if is_new and current:
                        paragraphs.append(" ".join(current))
                        current = []
                    current.append(frag)
                if current:
                    paragraphs.append(" ".join(current))

                for para in paragraphs:
                    if len(para) > 68:
                        for wline in textwrap.wrap(
                            para, width=68, break_long_words=False, break_on_hyphens=False
                        ):
                            self.add_message("system", colorize(wline, "dim"))
                    else:
                        self.add_message("system", colorize(para, "dim"))

                self.add_message(
                    "system", colorize("──────────────────────────────────────────", "dim")
                )
            self._motd_buf = []
            return True

        if code in (
            2,
            4,
            5,
            251,
            252,
            253,
            254,
            255,
            265,
            266,
            396,
        ):
            return True
        return False

    def _rpl_who(self, code, params, trailing):
        """WHO, ISON and WHOWAS replies."""
        if code == 352:
            _WHO_DISPLAY_MAX = 200
            _who_nick = params[5] if len(params) > 5 else ""
            _who_user = params[2] if len(params) > 2 else ""
            _who_host = params[3] if len(params) > 3 else ""
            _who_real = trailing or ""
            if _who_real and _who_real.startswith("0 "):
                _who_real = _who_real[2:]
            if not hasattr(self, "_otrv4_users"):
                self._otrv4_users: Dict[str, bool] = {}
            # Client identification only.  See otrv4_client_version().
            if _who_nick:
                self._otrv4_users[_who_nick] = advertises_otrv4(_who_real)
            if getattr(self, "_who_pending", False):
                _wc = getattr(self, "_who_count", 0)
                if _wc == 0:
                    self._who_count = 0
                if _wc < _WHO_DISPLAY_MAX:
                    _wp2 = self.panel_manager.active_panel or "system"
                    _m = colorize(" 🔵", "blue") if advertises_otrv4(_who_real) else ""
                    self.add_message(
                        _wp2,
                        f"  {colorize (_who_nick or '?','cyan'):<20}{_sanitise (_who_user +'@'+_who_host ,50 ):<40}{_sanitise (_who_real ,40 )}{_m }",
                    )
                    self._who_count += 1
                elif _wc == _WHO_DISPLAY_MAX:
                    _wp2 = self.panel_manager.active_panel or "system"
                    self.add_message(
                        _wp2,
                        colorize(
                            f"  … output capped at {_WHO_DISPLAY_MAX } rows - use /who in a smaller channel",
                            "yellow",
                        ),
                    )
                    self._who_count += 1
            return True

        if code == 303:
            _wp5 = self.panel_manager.active_panel or "system"
            _online = trailing or ""
            if _online.strip():
                self.add_message(
                    _wp5, colorize(f"ISON online: {_sanitise (_online ,256 )}", "green")
                )
            else:
                self.add_message(_wp5, colorize("ISON: none of those nicks are online", "dim"))
            return True
        if code == 314:
            _wp4 = self.panel_manager.active_panel or "system"
            _ww_nick = params[1] if len(params) > 1 else "?"
            _ww_user = params[2] if len(params) > 2 else ""
            _ww_host = params[3] if len(params) > 3 else ""
            _ww_real = trailing or ""
            self.add_message(
                _wp4, colorize("── WHOWAS ───────────────────────────────────", "dim")
            )
            self.add_message(
                _wp4,
                f"  {colorize_username (_ww_nick )}  {_sanitise (_ww_user +'@'+_ww_host ,80 )}  {_sanitise (_ww_real ,60 )}",
            )
            return True
        if code == 315:
            if getattr(self, "_who_pending", False):
                _wp3 = self.panel_manager.active_panel or "system"
                self.add_message(_wp3, colorize("─" * 56, "dim"))
                self._who_pending = False
                self._who_count = 0
            return True
        return False

    def _rpl_channel(self, code, params, trailing):
        """A channel's topic and its member list (NAMES)."""
        if code == 332:
            channel = params[1] if len(params) > 1 else ""
            topic = trailing or ""
            if channel in self.channels:
                self.channels[channel]["topic"] = topic
            self.add_message(channel or "system", f"Topic: {topic }")
            return True

        if code == 353:
            # ":server 353 me = #chan :@alice +bob carol"
            channel = params[2] if len(params) > 2 else ""
            if not channel:
                return True
            users = [u for u in (trailing.split() if trailing else [])
                     if split_names_entry(u)[1]]
            if channel not in self.names_data:
                self.names_data[channel] = []
            if not hasattr(self, "_names_total"):
                self._names_total = {}
            # The server's count, kept whole even when the local list is
            # capped, so the header reports the channel rather than the
            # slice of it we chose to render.
            self._names_total[channel] = self._names_total.get(channel, 0) + len(users)
            _nlim = getattr(self, "_names_limit", 500)
            _cur = len(self.names_data[channel])
            if _cur < _nlim:
                self.names_data[channel].extend(users[: _nlim - _cur])
            if channel in self.channels:
                for u in users:
                    self.channels[channel]["users"].add(split_names_entry(u)[1])
            return True

        if code == 366:
            channel = params[1] if len(params) > 1 else ""
            raw_users = self.names_data.get(channel, [])
            total = getattr(self, "_names_total", {}).pop(channel, None)
            if total is None:
                total = len(raw_users)
            self.names_data[channel] = []
            if getattr(self, "_pending_names_pager", None) != channel:
                # NAMES also arrives unsolicited on JOIN.  Accumulated
                # state is still cleared above, or it grows for the life
                # of the process and the next /names reports a stale
                # total.
                return True
            self._pending_names_pager = None
            lines, picks = format_names_list(
                raw_users,
                getattr(self, "_otrv4_users", {}),
                total=total,
                selectable=True,
            )
            chosen = self.pager.display(
                lines,
                f"Users in {_sanitise (channel ,64 )} ({total })",
                choices=picks,
            )
            if chosen:
                # Starting a DAKE, which is what actually authenticates
                # the peer.  Selecting a blue entry is a shortcut for
                # typing /otr <nick>; it confers no trust of its own.
                self.start_guided_otr_session(chosen)
            return True
        return False

    def _rpl_whois(self, code, params, trailing):
        """WHOIS replies."""
        if code == 311:
            target = params[1] if len(params) > 1 else ""
            user = params[2] if len(params) > 2 else ""
            host = params[3] if len(params) > 3 else ""
            real = trailing or ""
            # Both fields used to be computed from the local nick:
            # `Client` printed our own VERSION whatever the peer ran, and
            # `Name` printed TwentySevenClubNick.real_name(target), which
            # returns "<nick> - OTRv4+ <version>" for any nick at all.  So
            # /whois on a mIRC user reported them as an OTRv4+ client --
            # a claim derived from the nick, which is exactly the
            # inference this must not make.  Both now come off the wire.
            _peer_version = otrv4_client_version(real)
            if _peer_version:
                _client = colorize("OTRv4+ %s" % _peer_version, "blue")
            else:
                _client = colorize("not advertised", "dim")
            # Same reliable metadata as RPL_WHOREPLY, so /whois keeps the
            # /names marker current for that nick.
            if target:
                if not hasattr(self, "_otrv4_users"):
                    self._otrv4_users: Dict[str, bool] = {}
                self._otrv4_users[target] = _peer_version is not None
            _wp = self.panel_manager.active_panel or "system"
            self._whois_panel = _wp
            self.add_message(_wp, colorize("── WHOIS ─────────────────────────────────", "dim"))
            self.add_message(_wp, f"  Nick     : {colorize_username (target )}")
            self.add_message(_wp, f"  Client   : {_client }")
            self.add_message(
                _wp, f"  User     : {_sanitise (user ,64 )}@{_sanitise (host ,128 )}"
            )
            self.add_message(_wp, f"  Name     : {_sanitise (real ,128 )}")
            return True

        if code == 312:
            target = params[1] if len(params) > 1 else ""
            server = params[2] if len(params) > 2 else ""
            info = trailing or ""
            self.add_message(
                getattr(self, "_whois_panel", "system"),
                f"  Server   : {_sanitise (server ,128 )}"
                + (f" ({_sanitise (info ,256 )})" if info else ""),
            )
            return True

        if code == 313:
            target = params[1] if len(params) > 1 else ""
            self.add_message(
                getattr(self, "_whois_panel", "system"),
                f"  Status   : {colorize ('IRC Operator','yellow')}",
            )
            return True

        if code == 319:
            target = params[1] if len(params) > 1 else ""
            chans = trailing or ""
            self.add_message(
                getattr(self, "_whois_panel", "system"),
                f"  Channels : {_sanitise (chans ,512 )}",
            )
            return True

        if code == 317:
            target = params[1] if len(params) > 1 else ""
            idle_s = int(params[2]) if len(params) > 2 and params[2].isdigit() else 0
            signon = int(params[3]) if len(params) > 3 and params[3].isdigit() else 0
            idle_str = _fmt_duration(idle_s)
            if signon > 0:
                from datetime import datetime as _dt

                signon_str = _dt.fromtimestamp(signon).strftime("%Y-%m-%d %H:%M:%S")
                self.add_message(
                    getattr(self, "_whois_panel", "system"), f"  Idle     : {idle_str }"
                )
                self.add_message(
                    getattr(self, "_whois_panel", "system"), f"  Signon   : {signon_str }"
                )
            else:
                self.add_message(
                    getattr(self, "_whois_panel", "system"), f"  Idle     : {idle_str }"
                )
            return True

        if code == 301:
            target = params[1] if len(params) > 1 else ""
            away = trailing or ""
            self.add_message(
                getattr(self, "_whois_panel", "system"),
                f"  Away     : {colorize (_sanitise (away ,256 ),'yellow')}",
            )
            return True

        if code == 671:
            target = params[1] if len(params) > 1 else ""
            self.add_message(
                getattr(self, "_whois_panel", "system"),
                f"  Secure   : {colorize ('Yes (TLS)','green')}",
            )
            return True

        if code == 330:
            target = params[1] if len(params) > 1 else ""
            account = params[2] if len(params) > 2 else ""
            self.add_message(
                getattr(self, "_whois_panel", "system"),
                f"  Account  : {_sanitise (account ,64 )}",
            )
            return True

        if code == 318:
            self.add_message(
                getattr(self, "_whois_panel", "system"),
                colorize("──────────────────────────────────────────", "dim"),
            )
            return True
        return False

    def _rpl_other(self, code, params, trailing):
        """LIST, no-such-nick, and any other numeric with text."""
        if code == 321:
            self.channel_list = []
        elif code == 322:
            if len(params) >= 3:
                self.channel_list.append(
                    {
                        "channel": _sanitise(params[1], 64),
                        "users": int(params[2]) if params[2].isdigit() else 0,
                        "topic": _sanitise((trailing or "")[:60], 60),
                    }
                )
        elif code == 323:
            lines = [
                f"{colorize (c ['channel'],'green'):<20} {c ['users']:>4} users  {colorize (_sanitise (c ['topic'],256 ),'dim')}"
                for c in sorted(self.channel_list, key=lambda x: x["users"], reverse=True)
            ]
            self.pager.display(lines, "Channel list", f"{len (lines )} channels")

        elif code == 401:
            target = params[1] if len(params) > 1 else (params[0] if params else "")

            if target and self.session_manager.has_session(target):
                sess = self.session_manager.get_session(target)
                state = getattr(sess, "session_state", None) if sess else None

                if not hasattr(self, "_401_count"):
                    self._401_count = {}
                if not hasattr(self, "_401_handled"):
                    self._401_handled = set()

                self._401_count[target] = self._401_count.get(target, 0) + 1

                state_name = getattr(state, "name", str(state)) if state is not None else ""
                is_dake_phase = state_name in ("DAKE_IN_PROGRESS", "CREATED", "PLAINTEXT")

                if is_dake_phase and self._401_count[target] < 5:

                    self.debug(
                        "401 during DAKE",
                        {
                            "peer": target,
                            "state": state_name,
                            "count": self._401_count[target],
                        },
                    )
                elif target not in self._401_handled:
                    self._401_handled.add(target)
                    self._on_peer_disconnected(target, "nick no longer on server")
            elif trailing:
                self.add_message("system", colorize(f"⚠ {_sanitise (trailing ,512 )}", "dim"))

        elif trailing:
            self.add_message("system", colorize(trailing, "dim"))


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


def _run_input_loop(client, _select):
    """Read the keyboard until the user quits, then hand back to main."""
    def _print_prompt():
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

    client._prompt_refresh_cb = _print_prompt

    try:
        _print_prompt()
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
                                _print_prompt()
                            except KeyboardInterrupt:
                                safe_print(colorize("\nCtrl-C - type /quit to exit", "yellow"))
                                _print_prompt()
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
                    _print_prompt()
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
                    _print_prompt()

            except KeyboardInterrupt:
                safe_print(colorize("\nCtrl-C - type /quit to exit", "yellow"))
                _print_prompt()
            except Exception as exc:
                try:
                    client.debug(f"main loop error: {exc }")
                    client.add_message(
                        "system",
                        colorize(f"⚠ Internal error (recovered): {str (exc )[:80 ]}", "yellow"),
                    )
                except Exception:
                    pass
                _print_prompt()

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
        safe_print(colorize(_fail_hints.get(_fail_net, "Failed to connect."), "red"))
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
        safe_print(colorize("\nClean shutdown", "green"))

    atexit.register(_purge_on_exit)

    main()
