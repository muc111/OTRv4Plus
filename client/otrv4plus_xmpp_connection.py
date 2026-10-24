# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""The XMPP client's own stream: keepalive, sign-in failures, reconnecting.

A mixin of OTRv4PlusXMPP (otrv4plus_xmpp.py). Decides when the stream to
the server is dead (and, as importantly, when it is merely slow over I2P),
asks again for a refused password, and reconnects with backoff through a
fresh Tor or I2P forwarder."""
import asyncio
import os
import secrets
import sys
import time

import otrv4plus_ping as _ping
import otrv4plus_tunnels as _tunnels
from otrv4plus_term import print, _sanitise  # noqa: A004 (the client's print)

# Reconnect backoff constants.
_RECONNECT_BASE = 5    # seconds (initial delay)
_RECONNECT_MAX  = 300  # seconds (5 min ceiling)


#: The server limits sessions per account (Prosody mod_c2s_limit_sessions,
#: see docs/SECURITY_SESSIONS.md) and this account already has its quota.
SESSION_LIMIT_TEXT = (
    "this account is already signed in on another device, and the server "
    "allows only one session at a time.\n"
    "  Sign out on the other device (or wait a few minutes if it just lost "
    "its connection), then start again.\n"
    "  If the other session is not yours: change the password on the server "
    "(prosodyctl passwd) and end it (prosodyctl shell, c2s:close).")


def _is_session_limit(condition: str, raw: str) -> bool:
    """A policy-violation from a per-account session limit. Prosody's
    mod_c2s_limit_sessions says "Too many active connections to this
    account"; other policy refusals are left alone."""
    text = (condition + " " + raw).lower()
    return "policy-violation" in text and (
        "too many active connections" in text or "too many resources" in text)


class ConnectionMixin:
    """Keepalive, authentication failures and reconnects. Mixed into OTRv4PlusXMPP."""

    #: Whitespace cadence. Cheap, and its only job is keeping the I2P tunnel
    #: from being torn down for idleness.
    KEEPALIVE_WHITESPACE_S = 8

    #: Round-trip cadence, used only once the stream has gone quiet.
    KEEPALIVE_PING_S = 60

    #: How long the stream must have received NOTHING before a probe is worth
    #: sending.
    #:
    #: The first version of this keepalive probed unconditionally every 60 s
    #: and scored a slow reply as a failure. Measured on a 33-minute call that
    #: produced ten self-inflicted disconnects: in one case a rekey completed
    #: a full REKEY -> REKEYACK -> REKEYCOMMIT round trip through the server
    #: 3.2 s before the keepalive declared that same stream dead on "3 round
    #: trips in a row went unanswered" -- a verdict that takes ~3 minutes to
    #: accumulate. The stream was carrying bidirectional traffic throughout
    #: the window in which it was being scored as dead.
    #:
    #: The cause was already documented in this project before the keepalive
    #: existed, in VoiceCallManager: "IQ round-trips were deliberately
    #: avoided: over a 3-hop I2P path an IQ frequently exceeds slixmpp's reply
    #: timeout, whereas a <message> is fire-and-forget and traverses
    #: reliably." XEP-0199 is an IQ round trip.
    #:
    #: So a probe is now a last resort rather than a metronome. Any inbound
    #: stanza -- presence, a message, an OTR frame, rekey signalling -- is
    #: proof the whole path works, and proof outranks a slow ping. 180 s sits
    #: above VOICE_REKEY_SECONDS (120 s), so a live call refreshes this from
    #: its own signalling and never probes at all.
    KEEPALIVE_QUIET_S = 180

    #: How long to wait for a ping reply. Sized for a 3-hop I2P round trip
    #: under load rather than for a LAN: the old 30 s was shorter than the
    #: path's own latency and turned slowness into a verdict.
    KEEPALIVE_PING_TIMEOUT_S = 60

    #: Consecutive probe failures before the stream is declared dead. Each one
    #: already means KEEPALIVE_QUIET_S of total silence plus an unanswered
    #: ping, so two is strong evidence and the worst case is ~8 minutes.
    #:
    #: The bias is deliberate. Declaring a healthy stream dead costs a
    #: reconnect storm and an I2P tunnel rebuild; being slow to notice a
    #: genuinely dead one costs a delayed rekey, and a rekey that cannot be
    #: delivered already fails safe on the committed epoch. Media does not use
    #: XMPP at all.
    KEEPALIVE_PING_FAILS = 2

    def _note_inbound(self, stanza):
        """Record that the stream delivered something.  Returns it unchanged.

        Registered as a slixmpp inbound filter, so it sees presence, messages,
        IQs and everything else before any handler runs. It must never drop or
        alter a stanza -- returning it unchanged is the contract.
        """
        self._last_inbound = time.monotonic()
        return stanza

    def _stream_quiet_for(self) -> float:
        """Seconds since the stream last delivered anything."""
        return max(0.0, time.monotonic() - self._last_inbound)

    async def _probe_stream(self) -> bool:
        """Round-trip liveness check against our own server (XEP-0199).

        Returns True if the server answered AT ALL. An IqError counts as
        alive: a server replying `service-unavailable` to a ping has proven
        the stream works, which is the only thing being asked here. Treating
        it as death would reconnect against a perfectly good session.

        The round trip moved into `otrv4plus_ping`, shared with the Android
        transport, because this line was calling `async_ping` -- a method
        **slixmpp 1.17 does not have.** It was removed upstream in favour of
        `ping`, so on a current slixmpp this raised AttributeError, the bare
        `except Exception` read that as "no answer", and every probe reported
        a dead stream.

        Here the damage was hidden: the keepalive loop skips the probe
        entirely while the stream is delivering traffic, so an active
        conversation never pinged at all. A QUIET session -- one waiting on a
        reply, or holding a call open -- would still have been reconnected
        every couple of minutes for no reason. On Android, which had no such
        gate, it killed working sessions outright.

        A missing or unusable ping API is now `PingUnsupported` and counts as
        ALIVE. A client that cannot ask the question has learned nothing, and
        manufacturing a disconnect out of that is precisely the bug.
        """
        try:
            return await _ping.round_trip(
                self.plugin["xep_0199"], self.boundjid.host,
                self.KEEPALIVE_PING_TIMEOUT_S)
        except _ping.PingUnsupported:
            return True
        except asyncio.CancelledError:
            raise
        except Exception:
            # Reaching the plugin at all failed -- not an answer about the
            # server. Fail safe rather than reconnecting on our own confusion.
            return True

    def _declare_stream_dead(self, why: str) -> None:
        """Give up on the stream and let the reconnect logic take over.

        Breaking out of the keepalive loop is not enough on its own -- it
        only stops pinging. Something has to actually take the stream down so
        `_on_disconnected` fires and `_reconnect` runs.

        Any call in progress is deliberately left alone. Voice media rides
        its own I2P datagram session and does not touch XMPP once the call is
        up; only rekey signalling does, and a rekey that cannot be delivered
        already fails safe by keeping the committed epoch. Tearing down a
        working call because the control plane blinked would be the worse
        outcome by far.
        """
        print("[keepalive] %s — reconnecting. Any call in progress keeps "
              "running: media does not use XMPP." % why)
        try:
            result = self.disconnect()
            # slixmpp returns a coroutine here in some versions.
            if asyncio.iscoroutine(result):
                asyncio.ensure_future(result)
        except Exception as exc:
            print("[keepalive] disconnect failed: %s" % _sanitise(str(exc), 80))

    async def _keepalive_loop(self):
        """Keep the stream alive, and notice when it is not.

        Two mechanisms, because they answer different questions.

        **Whitespace, every 8 s.** Keeps an idle I2P tunnel from being torn
        down, which would drop the session during the long silences of an SMP
        exchange or a call where nothing is being typed.

        **A round trip, every 60 s.** This is the one that matters, and it
        was missing. `send_raw` only writes into the local socket buffer: it
        succeeds whether or not anything is still listening at the far end.
        Over I2P that is not a corner case -- the SAM stream can be gone
        while the local socket keeps accepting writes indefinitely -- so a
        whitespace-only keepalive reports a healthy stream forever, the
        failure counter never moves, `_on_disconnected` never fires, and
        reconnect never runs. The session dies silently and the first symptom
        is the peer appearing to go offline.

        A XEP-0199 ping requires the server to answer, so it proves the whole
        path rather than the first hop of it. On repeated timeout the stream
        is taken down explicitly, because breaking out of this loop on its
        own only stops pinging.

        Calls are never torn down here. Media rides its own I2P datagram
        session; only rekey signalling uses XMPP, and a rekey that cannot be
        delivered already fails safe by keeping the committed epoch.

        The loop is SILENT while it is working, including under --debug. A
        heartbeat that prints every 8 s forever reports nothing new — after
        the second line it is pure noise, and on a phone screen it buries the
        conversation it exists to protect. What is worth saying is a *change*:
        a probe that failed, and one that started working again.

        Set OTRV4PLUS_KEEPALIVE_TRACE=1 to watch every tick; /status reports
        the counters and the age of the last successful round trip.
        """
        trace = bool(os.environ.get("OTRV4PLUS_KEEPALIVE_TRACE"))
        whitespace_failures = 0
        next_probe = time.monotonic() + self.KEEPALIVE_PING_S

        # A new loop means a new stream, so the failure count starts again.
        #
        # It did not, and the effect was measured on a live call: the counter
        # is cleared only by a SUCCESSFUL probe, so after the first genuine
        # detection it stayed at the threshold. Every reconnect then began
        # one failure away from the limit, and a single missed ping
        # disconnected immediately -- the tolerance of three collapsed to
        # one. The live trace showed the counter climbing 3, 4, 5 with a
        # reconnect every ~96 s, which is exactly the ping interval plus the
        # timeout plus the sleep granularity: the period was this loop's own
        # signature, not the network's.
        self._keepalive_ping_fails = 0
        self._keepalive_degraded = False
        try:
            while not self._shutting_down:
                await asyncio.sleep(self.KEEPALIVE_WHITESPACE_S)
                if not self.is_connected():
                    # _on_disconnected owns the reconnect; this task is
                    # cancelled there and restarted by _on_start.
                    break
                self._keepalive_ticks += 1

                try:
                    self.send_raw(" ")
                    whitespace_failures = 0
                except Exception as exc:
                    whitespace_failures += 1
                    if whitespace_failures == 1:
                        print("[keepalive] whitespace write failed (%s)"
                              % _sanitise(str(exc), 80))
                    if whitespace_failures >= 3:
                        self._declare_stream_dead(
                            "the local socket stopped accepting writes")
                        break

                # Traffic is the best possible liveness evidence: it proves
                # the whole path, end to end, without asking the server for
                # anything. While it is arriving there is nothing to probe.
                quiet = self._stream_quiet_for()
                if quiet < self.KEEPALIVE_QUIET_S:
                    if self._keepalive_ping_fails or self._keepalive_degraded:
                        print("[keepalive] stream is delivering again "
                              "(traffic %.0fs ago)" % quiet)
                        self._keepalive_ping_fails = 0
                        self._keepalive_degraded = False
                    self._keepalive_last_ok = time.monotonic()
                    if trace:
                        print("[keepalive] tick %d (traffic %.0fs ago)"
                              % (self._keepalive_ticks, quiet))
                    continue

                if time.monotonic() < next_probe:
                    if trace:
                        print("[keepalive] tick %d (quiet %.0fs, probe due "
                              "in %.0fs)"
                              % (self._keepalive_ticks, quiet,
                                 next_probe - time.monotonic()))
                    continue

                next_probe = time.monotonic() + self.KEEPALIVE_PING_S
                self._keepalive_pings += 1
                alive = await self._probe_stream()

                if alive:
                    self._keepalive_last_ok = time.monotonic()
                    if self._keepalive_degraded:
                        print("[keepalive] server responding again after %d "
                              "missed round trip(s)"
                              % self._keepalive_ping_fails)
                        self._keepalive_degraded = False
                    self._keepalive_ping_fails = 0
                    if trace:
                        print("[keepalive] round trip %d ok"
                              % self._keepalive_pings)
                elif self._stream_quiet_for() < self.KEEPALIVE_QUIET_S:
                    # The reply never came, but something else did while we
                    # waited. The path works and the ping was merely slow --
                    # which over three I2P hops is ordinary, not a fault.
                    self._keepalive_last_ok = time.monotonic()
                    self._keepalive_ping_fails = 0
                    self._keepalive_degraded = False
                    if trace:
                        print("[keepalive] probe %d unanswered but traffic "
                              "arrived — not counted" % self._keepalive_pings)
                else:
                    self._keepalive_ping_fails += 1
                    # Lifetime tally, deliberately NOT reset per session: it
                    # is what distinguishes "one bad patch" from "this path
                    # degrades every couple of minutes" across a long call.
                    self._keepalive_timeouts += 1
                    if not self._keepalive_degraded:
                        # Said once, not once per probe.
                        self._keepalive_degraded = True
                        print("[keepalive] no reply from the server — the "
                              "I2P tunnel or the stream may be gone")
                    if self._keepalive_ping_fails >= self.KEEPALIVE_PING_FAILS:
                        self._declare_stream_dead(
                            "%d round trips in a row went unanswered"
                            % self._keepalive_ping_fails)
                        break
        except asyncio.CancelledError:
            pass

    MAX_AUTH_ATTEMPTS = 3

    def _on_failed_auth(self, event):
        """Offer a re-entry instead of ending the session on a typo.

        Retrying automatically with the SAME password would loop forever, so
        the reconnect loop stays blocked until a new one is supplied: while
        _password_prompt is set, _schedule_reconnect refuses to run. Only a
        password the user actually typed unblocks it.
        """
        self._auth_failures += 1
        left = self.MAX_AUTH_ATTEMPTS - self._auth_failures
        if left <= 0 or not self._can_prompt_for_password():
            print("\n[auth failed] the server rejected that password.",
                  file=sys.stderr)
            if left <= 0:
                print("[auth failed] %d attempts used — giving up. Check the "
                      "JID and restart." % self._auth_failures,
                      file=sys.stderr)
            self._shutting_down = True
            return
        print("\n[auth failed] the server rejected that password.")
        print("[auth] %d attempt%s left."
              % (left, "" if left == 1 else "s"))
        print("[auth] press Enter, then type the password again "
              "(it will not be shown).")
        self._password_prompt = "Password for %s: " % (self._own_bare or "?")

    def _can_prompt_for_password(self) -> bool:
        """True when a hidden prompt can actually be delivered.

        The plain reader owns stdin and can swap in getpass. The TUI draws
        and echoes its own input line, so a password typed there would be on
        screen and in any terminal capture; rather than leak it, that mode
        reports the failure and stays down.
        """
        if getattr(self, "_tui_enabled", False):
            return False
        try:
            return bool(sys.stdin.isatty())
        except Exception:
            return False

    def supply_password(self, text) -> None:
        """Accept a re-entered password and resume connecting."""
        if self._password_prompt is None:
            return
        self._password_prompt = None
        secret = (text or "").strip("\r\n")
        if not secret:
            print("[auth] nothing entered — session stays down.")
            self._shutting_down = True
            try:
                self.disconnect()
            except Exception:
                pass
            return
        # slixmpp's password setter writes credentials['password'], which is
        # what the next SASL attempt reads.
        self.password = secret
        self._reconnect_delay = _RECONNECT_BASE
        print("[auth] retrying with the new password…")
        self._schedule_reconnect("password re-entered")

    def _has_transport_params(self) -> bool:
        """True when reconnect knows which transport to re-establish.

        Reconnect is only scheduled when this holds. Without it the loop
        would run with no transport configured and take the direct-connect
        branch, which for an I2P or Tor session means silently exposing the
        user's address -- so "we do not know how to reconnect" has to mean
        "stay down", not "reconnect somehow".
        """
        return (self._sam_params is not None
                or getattr(self, "_tor_params", None) is not None)

    def _schedule_reconnect(self, why: str) -> None:
        """Start the reconnect loop unless one is already running.

        Every path that wants a reconnect goes through here. _on_disconnected
        and _on_connection_failed both fire during a failed reconnect attempt,
        and they used to schedule independently -- one of them without even
        recording the task, so it was invisible to the other's guard. The
        result was two loops with independent backoff delays both calling
        connect(), and on I2P two SAM forwarders being built for one session.
        """
        if self._shutting_down or not self._has_transport_params():
            return
        if self._password_prompt is not None:
            # Reconnecting now would present the password the server has
            # already rejected, and do it every few seconds forever.
            return
        existing = self._reconnect_task
        if existing is not None and not existing.done():
            return
        try:
            loop = asyncio.get_event_loop()
            self._reconnect_task = loop.create_task(self._reconnect())
        except Exception as exc:
            print("[reconnect] could not schedule after %s: %s"
                  % (why, _sanitise(str(exc), 80)))

    def _on_disconnected(self, event):
        print("\n[disconnected]")
        if self._keepalive_task:
            self._keepalive_task.cancel()
        # A trade belongs to the session it was agreed in. Carrying one across
        # a reconnect would mean resuming a financial coordination against a
        # peer whose fingerprint has not been re-checked and whose SMP state
        # has been torn down with the session -- so it is dropped, loudly.
        self._clear_trades("the session ended")
        # Our stream is what went away. Every peer will look unavailable for
        # the duration, and none of them has actually gone anywhere.
        self._clear_peer_gone("our transport dropped")
        self._schedule_reconnect("disconnect")

    def _on_connection_failed(self, event):
        reason = str(event) if event else "unknown"
        print(f"[connection failed] {_sanitise(reason, 256)}")
        self._schedule_reconnect("connection failure")

    # Stream errors that will NEVER succeed on retry. Reconnecting after one
    # of these rebuilds an I2P tunnel every few seconds forever, burning
    # bandwidth and hiding the real cause behind a wall of reconnect noise.
    _FATAL_STREAM_ERRORS = {
        "host-unknown": (
            "the server does not serve the domain in your --jid.\n"
            "  Your JID domain must match the server's VirtualHost.\n"
            "  If you connect by .b32.i2p address, pass it with --server and\n"
            "  keep the configured host name in --jid, e.g.\n"
            "    --jid you@yourhost.i2p --server <b32>.b32.i2p"),
        "not-authorized": "the server rejected this account or password.",
        "unsupported-version": "the server requires a different XMPP version.",
        "invalid-namespace": "protocol mismatch — is this an XMPP server?",
        "see-other-host": "the server redirected to another host.",
        # Replaced by a newer sign-in of this account (the server keeps only
        # the newest). Reconnecting would sign that one out in turn.
        "conflict": "signed out: this account signed in somewhere else, and "
                    "the server keeps only the newest sign-in.\n"
                    "  Start the client again to use it here (that signs the "
                    "other one out).\n"
                    "  If it was not you, change your password.",
    }

    def _on_stream_error(self, error):
        raw = str(error)
        condition = getattr(error, "condition", None) or raw
        print(f"[stream error] {_sanitise(str(condition), 256)}")

        # slixmpp does not always populate .condition, so fall back to
        # matching the element name inside the raw stanza.
        matched = None
        if _is_session_limit(str(condition), raw):
            self._shutting_down = True
            print("\n[fatal] %s\n" % SESSION_LIMIT_TEXT)
            try:
                self.disconnect()
            except Exception:
                pass
            return
        if "resource-constraint" in (str(condition), raw) or \
                "<resource-constraint" in raw:
            # mod_otrv4plus_capacity: as many people online as it allows,
            # or sign-ins paced. Not fatal: the reconnect loop tries again
            # (with a randomised delay), and gets in once there is room.
            if "busy" in raw.lower():
                print("[server] the server is letting people in a few at a "
                      "time; trying again in a moment.")
            else:
                print("[server] the server is full (as many people online as "
                      "it allows); trying again shortly.")
            return
        for name in self._FATAL_STREAM_ERRORS:
            if name == str(condition) or ("<%s " % name) in raw or (
                    "<%s>" % name) in raw:
                matched = name
                break
        if matched is None:
            return

        self._shutting_down = True          # stop the reconnect loop
        print("\n[fatal] %s" % self._FATAL_STREAM_ERRORS[matched])
        if matched == "conflict":
            print()
        else:
            print("[fatal] Not retrying — this cannot succeed without a change "
                  "to your arguments or the server configuration.\n")
        try:
            self.disconnect()
        except Exception:
            pass

    async def _reconnect(self):
        """Exponential-backoff reconnect. Re-establishes the I2P SAM tunnel
        before reconnecting slixmpp when running over I2P."""
        while not self._shutting_down:
            # Spread by ±25%, as the app does: after a server restart every
            # client drops at once, and the server paces sign-ins
            # (mod_otrv4plus_capacity), so arriving together means waiting.
            delay = round(self._reconnect_delay
                          * (0.75 + secrets.randbelow(501) / 1000), 1)
            print(f"[reconnect] waiting {delay}s before reconnecting...")
            await asyncio.sleep(delay)
            if self._shutting_down:
                return
            # The resource is what changes across a reconnect, and the next
            # live test needs to show whether it changes cleanly. The bare
            # JID is already on screen from [connected]; only the resource is
            # added here, and it is server-assigned rather than secret.
            before = ""
            try:
                before = self.boundjid.resource or ""
            except Exception:
                pass
            self._reconnects_started = getattr(self, "_reconnects_started",
                                               0) + 1
            print("[reconnect] attempt %d, resource before=%s"
                  % (self._reconnects_started,
                     _sanitise(before, 40) or "(none)"))
            try:
                if self._is_i2p and self._sam_params:
                    p = self._sam_params
                    try:
                        host, port = await _tunnels.start_i2p_sam_forwarder(
                            p["server_b32"],
                            p["dest_port"],
                            sam_host=p["sam_host"],
                            sam_port=p["sam_port"],
                        )
                    except Exception as e:
                        print(f"[reconnect] SAM bridge failed: {e}")
                        self._reconnect_delay = min(
                            self._reconnect_delay * 2, _RECONNECT_MAX
                        )
                        continue
                    self.connect(host, port)
                elif getattr(self, "_is_tor", False) and self._tor_params:
                    p = self._tor_params
                    try:
                        host, port = await _tunnels.start_tor_socks_forwarder(
                            p["onion_host"],
                            p["dest_port"],
                            socks_host=p["socks_host"],
                            socks_port=p["socks_port"],
                        )
                    except Exception as e:
                        print(f"[reconnect] Tor tunnel failed: {e}")
                        self._reconnect_delay = min(
                            self._reconnect_delay * 2, _RECONNECT_MAX
                        )
                        continue
                    self.connect(host, port)
                elif getattr(self, "_is_tor", False):
                    # Same reasoning as the I2P guard below: the fall-through
                    # would open a direct connection from a session the user
                    # asked to route through Tor.
                    print("[reconnect] REFUSING to reconnect: this session is "
                          "Tor but the SOCKS parameters are missing. Falling "
                          "back to a direct connection would expose your "
                          "address, so the session stays down.")
                    return
                elif self._is_i2p:
                    # Unreachable today: _sam_params and _is_i2p are set
                    # together, and _on_disconnected only schedules this loop
                    # when _sam_params is not None. It is guarded anyway
                    # because of what the fall-through WOULD do -- open a
                    # direct clearnet connection to the XMPP server from a
                    # session the user asked to run over I2P, silently
                    # exposing their address. A transport downgrade must
                    # never be reachable by one condition drifting.
                    print("[reconnect] REFUSING to reconnect: this session is "
                          "I2P but the SAM parameters are missing. Falling "
                          "back to a direct connection would expose your "
                          "address, so the session stays down.")
                    return
                else:
                    self.connect()
                self._reconnects_completed = getattr(
                    self, "_reconnects_completed", 0) + 1
                print("[reconnect] transport re-established (%d/%d). "
                      "[connected] will report the new resource."
                      % (self._reconnects_completed,
                         self._reconnects_started))
                return  # _on_start resets _reconnect_delay on success
            except Exception as e:
                print(f"[reconnect] failed: {e}")
                self._reconnect_delay = min(
                    self._reconnect_delay * 2, _RECONNECT_MAX
                )
