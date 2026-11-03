# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""The IRC client's protocol handling: parsing lines, CAP/SASL, and the
handlers for messages, membership, identity and numeric replies.

A mixin of OTRv4IRCClient (otrv4plus_irc.py); the methods moved here
unchanged."""
import textwrap
import threading
import time
from otrv4plus import IRCConstants, _sanitise, _secure_wipe, advertises_otrv4, colorize, colorize_username, format_names_list, otrv4_client_version, split_names_entry
from otrv4plus_irc_util import TwentySevenClubNick, _fmt_duration
from typing import List, Optional


class IrcProtocolMixin:
    """See the module docstring."""


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
