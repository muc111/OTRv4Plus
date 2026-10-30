# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""The IRC client's connection: the proxy or SAM socket, the receive loop,
reconnecting, and keeping OTR sessions and the nick across a reconnect.

A mixin of OTRv4IRCClient (otrv4plus_irc.py); the methods moved here
unchanged."""
import secrets
import socket
import struct
import threading
import time
from otrv4plus import I2PSAMConnection, IRCConstants, NetworkConstants, UIConstants, _probe_socks5, _sanitise, colorize, colorize_username, socks
from otrv4plus_irc_util import TwentySevenClubNick


class IrcNetMixin:
    """See the module docstring."""


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
