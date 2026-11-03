# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""The IRC client's sending: line pacing against flood limits, the measured
send rate, and fragmenting OTR messages to fit a line.

A mixin of OTRv4IRCClient (otrv4plus_irc.py); the methods moved here
unchanged."""
import time
from otrv4plus import NetworkConstants, UIConstants, _sanitise, _set_prompt, colorize
from typing import Optional


class IrcPacingMixin:
    """See the module docstring."""


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
