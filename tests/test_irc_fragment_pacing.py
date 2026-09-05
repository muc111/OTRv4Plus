"""How fast OTR fragments may leave, and who decides.

A 12 KiB SMP2 is 48 IRC lines. On a real handshake over irc.postman.i2p a full
verification took seventeen minutes, and about ten of those were this client
sleeping between lines -- not I2P latency and not the PQC computation.

The I2P path slept 6s after every second fragment: an average of 3.15s a line.
The clearnet path in the same function had always used the model mainstream
ircds actually implement -- a leaky bucket, each line costing a fixed penalty,
the allowance refilling one second per second -- at 2.0s a line with a burst.
The overlay path was paying roughly double for no stated reason.

WHAT THIS FILE IS CAREFUL ABOUT
===============================
Going faster is only free until the server disagrees, and a disconnect
mid-DAKE costs several minutes to rebuild on I2P. So three things are asserted
rather than one:

  * the pacing is the ircd model, not a new invention;
  * evidence of throttling drops the rate immediately and never raises it
    again on its own;
  * the derived fragment size can only ever improve on the value that was
    already known to work, and is bounded above.

The sweet spot for a given server cannot be derived, only found. `/fragrate`
exists so it can be found with evidence -- it reports what the last send
actually achieved -- rather than by feel.
"""

import pytest

otr = pytest.importorskip("otrv4plus")

CLIENT = otr.EnhancedOTRv4IRCClient
BASE = otr.OTRv4IRCClient
NET = otr.NetworkConstants


class Clock:
    """Time under the test's control: pacing is arithmetic, not sleeping."""

    def __init__(self):
        self.now = 0.0
        self.slept = []

    def sleep(self, secs):
        self.slept.append(secs)
        self.now += secs

    def __call__(self):
        return self.now


def run_pacer(preset, n, clock=None):
    """Total seconds a pacer would spend sending *n* lines."""
    clock = clock or Clock()
    cost, allowance, cap, floor = BASE.PACE_PRESETS[preset]
    pacer = BASE._Pacer(cost, allowance, cap, floor,
                        sleep=clock.sleep, clock=clock)
    for _ in range(n):
        pacer.wait()
    return clock.now


class Client:
    METHODS = ("_pacer", "_pace_name", "_cmd_fragrate", "_fragment_size",
               "_note_possible_flood", "_record_send_rate",
               "_rate_sample_min")

    #: The stub stands in for the class, so it carries the class attributes
    #: the borrowed methods read. Referenced, not copied: a preset changed in
    #: production must not leave these tests asserting a stale number.
    PACE_PRESETS = BASE.PACE_PRESETS
    DEFAULT_PACE = BASE.DEFAULT_PACE
    FLOOD_MARKERS = BASE.FLOOD_MARKERS
    FRAG_SIZE_MIN = BASE.FRAG_SIZE_MIN
    FRAG_SIZE_MAX = BASE.FRAG_SIZE_MAX
    FRAG_SIZE_FLOOR = BASE.FRAG_SIZE_FLOOR
    FRAG_SAFETY_MARGIN = BASE.FRAG_SAFETY_MARGIN
    FRAG_ASSUMED_USERHOST = BASE.FRAG_ASSUMED_USERHOST
    RATE_SAMPLE_PACED_LINES = BASE.RATE_SAMPLE_PACED_LINES
    _Pacer = BASE._Pacer

    def __init__(self, server="irc.postman.i2p"):
        self.lines = []
        self.server = server
        self.nick = "WildSignal"
        for name in self.METHODS:
            setattr(self, name, getattr(CLIENT, name).__get__(self))

    def add_message(self, target, message, sec=None):
        self.lines.append(str(message))

    def debug(self, *a, **k):
        pass

    def said(self, needle):
        return any(needle in line for line in self.lines)


@pytest.fixture
def client():
    return Client()


class TestThePacingIsTheIrcdModel:
    """Not a new invention: the same leaky bucket the clearnet path has always
    used, and the one an ircd's penalty counter implements."""

    def test_the_first_lines_go_out_on_the_burst_allowance(self):
        """A 4-second allowance at 2s a line is two lines before the penalty
        bites. They still pay the inter-line floor -- blasting even two lines
        back to back into an I2P tunnel buys nothing -- but not the 2s."""
        cost, allowance, _cap, floor = BASE.PACE_PRESETS["normal"]
        assert run_pacer("normal", 2) == pytest.approx(2 * floor, abs=0.001)
        assert run_pacer("normal", 2) < cost

    def test_the_sustained_rate_is_the_penalty(self):
        """Twelve lines: two free, ten at 2s."""
        assert run_pacer("normal", 12) == pytest.approx(20.0, abs=0.01)

    def test_the_allowance_does_not_grow_past_the_cap(self):
        """A long idle period must not buy an unbounded burst -- that is
        precisely what an ircd's cap prevents, and mirroring it is the point
        of using their model.

        Built with the inter-line floor at zero on purpose: with a floor
        every call sleeps, so "did this line wait?" cannot distinguish a
        capped bucket from an uncapped one. An earlier version of this test
        had exactly that hole and a mutant removing the cap survived it."""
        clock = Clock()
        cost, allowance, cap, _floor = BASE.PACE_PRESETS["normal"]
        pacer = BASE._Pacer(cost, allowance, cap, 0.0,
                            sleep=clock.sleep, clock=clock)
        clock.now += 3600.0
        free = 0
        for _ in range(40):
            before = clock.now
            pacer.wait()
            if clock.now == before:
                free += 1
            else:
                break
        assert free <= cap / cost, (
            "an hour idle bought %d free lines; the cap allows %d"
            % (free, cap / cost))

    @pytest.mark.parametrize("preset", ["safe", "normal", "fast", "turbo"])
    def test_every_preset_paces_something(self, preset):
        assert run_pacer(preset, 48) > 0


class TestItIsActuallyFasterThanWhatItReplaced:
    """The measured claim, on the message that dominates the handshake."""

    @staticmethod
    def old_i2p_pacing(n):
        """The behaviour being replaced: 6s after every second fragment."""
        return sum(6.0 if i % 2 == 0 else 0.30 for i in range(1, n))

    def test_a_48_fragment_smp2_is_meaningfully_quicker(self):
        old = self.old_i2p_pacing(48)
        new = run_pacer("normal", 48)
        assert new < old * 0.70, (
            "expected a clear improvement on 3.15s/line; got %.1fs vs %.1fs"
            % (new, old))

    def test_the_default_is_the_rate_known_to_survive(self):
        """v10.25.0 defaulted to `normal` on the arithmetic. The first real
        run at it ended with the server closing the connection, so the
        default is the conservative rate again -- the one the user already
        had working -- and the faster ones are opt-in.

        This is not a claim that the pacing caused that disconnect. No ERROR
        line arrived and the disconnected side was idle at the time. It is a
        claim that a default should be the value with evidence behind it."""
        assert BASE.DEFAULT_PACE == "safe"
        # At the sizes that actually occur -- every DAKE and SMP message is
        # 16 to 48 fragments -- it reproduces the old rate closely. That is
        # what "known to survive" means: the same lines/sec on the wire.
        for n in (16, 24, 48):
            assert run_pacer(BASE.DEFAULT_PACE, n) == \
                pytest.approx(self.old_i2p_pacing(n), rel=0.05)

    def test_the_default_tracks_the_old_schedule_to_within_one_line(self):
        """The two are not identical at every count and do not need to be.
        The old schedule paid its 6s pause BEFORE every second line, so at an
        odd number of fragments it has already paid a pause the bucket has
        not -- a phase offset of at most one line's cost, in either
        direction. The sustained rate is what matters and it is the same.

        Bounded rather than one-sided, because "never faster" turned out to
        be false for a reason that is not a problem, and a test asserting it
        would have been testing the phase rather than the rate."""
        cost = BASE.PACE_PRESETS["safe"][0]
        for n in range(2, 60):
            drift = run_pacer("safe", n) - self.old_i2p_pacing(n)
            assert abs(drift) <= cost + 0.01, (
                "safe drifts %.2fs from the old schedule at %d fragments, "
                "more than the one-line offset the two shapes explain"
                % (drift, n))

    def test_the_faster_rates_are_still_available(self):
        """Backing off the default must not remove the tuning surface --
        finding the sweet spot is the whole point of /fragrate."""
        for preset in ("normal", "fast", "turbo"):
            assert run_pacer(preset, 48) < self.old_i2p_pacing(48) * 0.75

    def test_safe_reproduces_roughly_the_old_rate(self):
        """`safe` is kept because it is the one rate known to survive on
        irc.postman.i2p. If it drifted far from what was tested, falling back
        to it would not be a fallback."""
        old = self.old_i2p_pacing(48)
        assert run_pacer("safe", 48) == pytest.approx(old, rel=0.15)


class TestTheRateIsChosenPerNetwork:

    def test_i2p_uses_the_selected_preset(self, client):
        client._pace_preset = "fast"
        pacer = client._pacer(NET.NET_I2P)
        assert pacer.cost == BASE.PACE_PRESETS["fast"][0]

    def test_clearnet_ignores_the_preset(self, client):
        """The preset exists to tune an overlay where the round trip dwarfs
        the pacing. Loosening a clearnet connection with it would be tuning
        the wrong thing, against a server nobody measured."""
        client._pace_preset = "turbo"
        pacer = client._pacer(NET.NET_CLEARNET)
        assert pacer.cost == BASE.PACE_PRESETS["normal"][0]

    def test_tor_keeps_a_floor_between_lines(self, client):
        pacer = client._pacer(NET.NET_TOR)
        assert pacer.floor >= 0.20

    def test_the_default_applies_with_nothing_set(self, client):
        assert client._pace_name() == BASE.DEFAULT_PACE


class TestEvidenceOfThrottlingDropsTheRate:

    @pytest.mark.parametrize("reason", [
        "Closing Link: WildSignal[i2p] (Excess Flood)",
        "Max SendQ exceeded",
        "You are being throttled",
        "Too many lines in a short time",
    ])
    def test_a_flood_complaint_drops_to_safe(self, client, reason):
        client._pace_preset = "turbo"
        assert client._note_possible_flood(reason) is True
        assert client._pace_name() == "safe"

    def test_the_user_is_told_why_it_slowed_down(self, client):
        client._pace_preset = "fast"
        client._note_possible_flood("Closing Link: x (Excess Flood)")
        assert client.said("complained about the send rate")

    def test_nothing_is_said_when_it_is_already_safe(self, client):
        """The default is `safe`, so most flood complaints have nothing to
        change. Announcing a change that did not happen is noise at exactly
        the moment the user needs the real reason."""
        client._note_possible_flood("Closing Link: x (Excess Flood)")
        assert not client.said("complained about the send rate")

    def test_an_ordinary_error_does_not_change_anything(self, client):
        client._pace_preset = "fast"
        assert client._note_possible_flood("Closing Link: ping timeout") is False
        assert client._pace_name() == "fast"

    def test_it_is_never_raised_again_automatically(self, client):
        """A server that threw us off once will do it again. An automatic
        recovery rediscovers the limit the expensive way, mid-handshake."""
        client._note_possible_flood("excess flood")
        for _ in range(5):
            client._note_possible_flood("something harmless")
        assert client._pace_name() == "safe"

    def test_it_says_nothing_twice(self, client):
        client._note_possible_flood("excess flood")
        first = len(client.lines)
        client._note_possible_flood("excess flood")
        assert len(client.lines) == first

    def test_an_empty_reason_is_not_a_flood(self, client):
        assert client._note_possible_flood("") is False
        assert client._note_possible_flood(None) is False


class TestTheFragmentSizeIsMeasuredNotGuessed:
    """The binding limit is the line the RECIPIENT sees, which carries a
    prefix the server adds after we send."""

    def test_without_a_known_prefix_it_assumes_the_worst_user_and_host(
            self, client):
        """Not a fixed 380: our own nick and the target are known, so only
        user@host has to be assumed, and it is assumed at its maximum."""
        client.nick = "WildSignal"
        size = client._fragment_size("RusticShade", NET.NET_I2P)
        line = (":" + client.nick + "!" + "u" * 10 + "@" + "h" * 63
                + " PRIVMSG RusticShade :" + "F" * size + "\r\n")
        assert len(line.encode()) <= 512

    def test_the_unknown_prefix_case_is_no_worse_than_the_old_fixed_value(
            self, client):
        client.nick = "WildSignal"
        assert client._fragment_size("RusticShade", NET.NET_I2P) >= \
            BASE.FRAG_SIZE_MIN

    def test_a_short_prefix_buys_a_bigger_fragment(self, client):
        client._own_prefix = "Nick!u@short.i2p"
        assert client._fragment_size("peer", NET.NET_I2P) > BASE.FRAG_SIZE_MIN

    def test_a_longer_prefix_buys_a_smaller_fragment(self, client):
        client._own_prefix = "WildSignal!user@" + "a" * 52 + ".b32.i2p"
        long_prefix = client._fragment_size("peer", NET.NET_I2P)
        client._own_prefix = "n!u@short.i2p"
        assert client._fragment_size("peer", NET.NET_I2P) > long_prefix

    def test_the_worst_realistic_case_still_fits(self, client):
        """Longest plausible everything: a 30-char nick, a b32 host, and a
        30-char target. If this overflowed, the floor would be too high."""
        client._own_prefix = "N" * 30 + "!user@" + "a" * 52 + ".b32.i2p"
        size = client._fragment_size("T" * 30, NET.NET_I2P)
        line = (":" + client._own_prefix + " PRIVMSG " + "T" * 30 + " :"
                + "F" * size + "\r\n")
        assert len(line.encode()) <= 512

    def test_it_never_exceeds_the_ceiling(self, client):
        client._own_prefix = "a!b@c"
        assert client._fragment_size("x", NET.NET_I2P) <= BASE.FRAG_SIZE_MAX

    def test_the_computed_line_fits_in_512_bytes(self, client):
        """The property the arithmetic exists for, checked end to end."""
        for host in ("short.i2p", "a" * 20 + ".i2p", "a" * 52 + ".b32.i2p"):
            client._own_prefix = "WildSignal!user@" + host
            for target in ("p", "RusticShade", "x" * 30):
                size = client._fragment_size(target, NET.NET_I2P)
                line = (":" + client._own_prefix + " PRIVMSG " + target
                        + " :" + "F" * size + "\r\n")
                assert len(line.encode()) <= 512, (
                    "a %d-byte fragment overflows the recipient's line"
                    % size)

    def test_a_long_target_shrinks_the_fragment(self, client):
        client._own_prefix = "n!u@short.i2p"
        short = client._fragment_size("ab", NET.NET_I2P)
        long_ = client._fragment_size("x" * 30, NET.NET_I2P)
        assert long_ <= short

    def test_the_safety_margin_is_real_slack(self, client):
        """The margin is what absorbs a prefix the server changes after we
        measured it -- a vhost applied post-JOIN. With it at zero the line is
        exactly 512 and any such change truncates a fragment."""
        assert BASE.FRAG_SAFETY_MARGIN >= 4
        client._own_prefix = "WildSignal!user@" + "a" * 20 + ".i2p"
        size = client._fragment_size("RusticShade", NET.NET_I2P)
        line = (":" + client._own_prefix + " PRIVMSG RusticShade :"
                + "F" * size + "\r\n")
        assert 512 - len(line.encode()) >= BASE.FRAG_SAFETY_MARGIN, (
            "no slack left below the line limit")

    def test_clearnet_is_untouched(self, client):
        client._own_prefix = "n!u@short"
        assert client._fragment_size("peer", NET.NET_CLEARNET) == \
            otr.UIConstants.OTR_FRAGMENT_SIZE

    def test_a_prefix_without_user_or_host_is_not_trusted(self, client):
        """A bare nick under-counts the overhead by the whole user@host the
        server adds, and the failure mode is a truncated line -- a corrupted
        OTR message rather than a slow one. It must fall back to assuming the
        worst, not take the short prefix at face value."""
        client.nick = "JustANick"
        unset = client._fragment_size("peer", NET.NET_I2P)
        client._own_prefix = "JustANick"
        assert client._fragment_size("peer", NET.NET_I2P) == unset, (
            "a bare nick was treated as a full prefix, under-counting the "
            "overhead by the user@host the server adds")
        # And the difference is real rather than hidden by the ceiling: taking
        # the bare nick at face value computes a bigger fragment than the
        # ceiling allows, which is how a mutant removing this check survived
        # an earlier version of this test.
        face_value = 512 - (1 + len("JustANick") + 9 + len("peer") + 2 + 2
                            + BASE.FRAG_SAFETY_MARGIN)
        assert face_value > BASE.FRAG_SIZE_MAX

    def test_the_floor_never_overrides_a_smaller_computed_limit(self, client):
        """The bug this class found. `max(380, computed)` returned 380 when
        the real limit was 364, and the server truncated the line along with
        the fragment's terminating "." -- corrupting the message rather than
        slowing it. A floor may be a fallback for not knowing; it may never
        override knowing."""
        client._own_prefix = "N" * 30 + "!user@" + "a" * 52 + ".b32.i2p"
        size = client._fragment_size("T" * 30, NET.NET_I2P)
        assert size < BASE.FRAG_SIZE_MIN
        line = (":" + client._own_prefix + " PRIVMSG " + "T" * 30 + " :"
                + "F" * size + "\r\n")
        assert len(line.encode()) <= 512

    def test_the_old_fixed_value_would_have_overflowed_there(self, client):
        """Pinning the pre-existing bug so the arithmetic cannot quietly go
        back to a constant."""
        prefix = "N" * 30 + "!user@" + "a" * 52 + ".b32.i2p"
        line = (":" + prefix + " PRIVMSG " + "T" * 30 + " :"
                + "F" * BASE.FRAG_SIZE_MIN + "\r\n")
        assert len(line.encode()) > 512


class TestTheCommand:

    def test_it_reports_the_current_setting(self, client):
        client._cmd_fragrate("")
        assert client.said("Fragment pacing: %s" % BASE.DEFAULT_PACE)

    def test_it_sets_a_known_preset(self, client):
        client._cmd_fragrate("fast")
        assert client._pace_name() == "fast"

    def test_it_refuses_an_unknown_one(self, client):
        client._cmd_fragrate("ludicrous")
        assert client._pace_name() == BASE.DEFAULT_PACE
        assert client.said("Usage:")

    def test_the_aggressive_presets_come_with_the_caveat(self, client):
        client._cmd_fragrate("turbo")
        assert client.said("disconnects you mid-handshake")

    def test_it_reports_what_the_last_send_achieved(self, client):
        """The measurement is the point: a rate is raised, tried on a real
        handshake, and kept or reverted on evidence."""
        client._record_send_rate(48, 96.0)
        client._cmd_fragrate("")
        assert client.said("48 fragments")
        assert client.said("0.50 lines/sec")

    def test_it_says_when_there_is_nothing_measured_yet(self, client):
        client._cmd_fragrate("")
        assert client.said("No multi-fragment send yet")

    def test_it_reports_whether_the_prefix_was_measured(self, client):
        client._cmd_fragrate("")
        assert client.said("prefix not seen yet")
        client._own_prefix = "n!u@short.i2p"
        client.lines.clear()
        client._cmd_fragrate("")
        assert client.said("from the server-reported prefix")

    def test_a_single_fragment_send_is_not_recorded(self, client):
        client._record_send_rate(1, 5.0)
        assert getattr(client, "_last_send_stats", None) is None

    def test_a_heartbeat_does_not_clobber_a_real_measurement(self, client):
        """Seen on a handset: `/fragrate` reported "2 fragments in 0.6s
        (3.32 lines/sec)" on a preset whose sustained rate is 0.32, because a
        60-second heartbeat had overwritten the measurement of a 23-fragment
        SMP1 -- at the moment the number was being read to decide whether to
        go faster.

        Both fragments of a heartbeat come out of the burst allowance without
        waiting, so it measures the burst and calls it the rate."""
        client._record_send_rate(23, 66.7)
        client._record_send_rate(2, 0.6)
        stats = client._last_send_stats
        assert stats["fragments"] == 23, (
            "a 2-fragment heartbeat overwrote the real sample")
        assert stats["lines_per_sec"] < 1.0

    @pytest.mark.parametrize("n", [2, 3, 4])
    def test_sends_too_short_to_measure_are_ignored(self, client, n):
        client._record_send_rate(n, 0.5)
        assert getattr(client, "_last_send_stats", None) is None

    def test_a_send_long_enough_to_pace_is_recorded(self, client):
        client._record_send_rate(client._rate_sample_min(), 12.0)
        assert client._last_send_stats["fragments"] == \
            client._rate_sample_min()

    @pytest.mark.parametrize("preset", ["safe", "normal", "fast", "turbo"])
    def test_the_threshold_always_leaves_the_burst_behind(self, client, preset):
        """The sample has to contain paced lines, not just the allowance --
        and how many lines are free depends on the preset. A fixed threshold
        of 5 is three paced lines on `safe` and pure burst on `turbo`, whose
        allowance clears eight."""
        client._pace_preset = preset
        cost, allowance, _cap, _floor = BASE.PACE_PRESETS[preset]
        burst = allowance / cost
        assert client._rate_sample_min() >= burst + BASE.RATE_SAMPLE_PACED_LINES

    def test_a_pure_burst_sample_is_refused_on_every_preset(self, client):
        for preset in BASE.PACE_PRESETS:
            client._pace_preset = preset
            client._last_send_stats = None
            cost, allowance, _c, _f = BASE.PACE_PRESETS[preset]
            client._record_send_rate(int(allowance // cost), 0.4)
            assert client._last_send_stats is None, (
                "%s recorded a sample that was entirely burst" % preset)


class TestItIsWiredIn:
    """The v10.23.2 lesson: a command in the base class is not reachable if
    the subclass claims it, and a helper nothing calls is not a change."""

    @staticmethod
    @pytest.fixture(scope="class")
    def tree():
        import ast
        import os
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(root, "otrv4+.py"), encoding="utf-8") as fh:
            return ast.parse(fh.read())

    def test_fragrate_reaches_the_handler_on_the_running_class(self, client):
        """Driven, not grepped: the subclass must not shadow it."""
        c = Client()
        c.handle_command = CLIENT.handle_command.__get__(c)
        c.handle_command("fragrate turbo")
        assert c._pace_name() == "turbo"

    def test_the_send_path_uses_the_pacer(self, tree):
        import ast
        fn = next(n for n in ast.walk(tree)
                  if isinstance(n, ast.FunctionDef)
                  and n.name == "send_otr_message")
        src = ast.unparse(fn)
        assert "_pacer(" in src and "_pace.wait()" in src

    def test_the_old_modulo_sleep_is_gone(self, tree):
        import ast
        fn = next(n for n in ast.walk(tree)
                  if isinstance(n, ast.FunctionDef)
                  and n.name == "send_otr_message")
        src = ast.unparse(fn)
        assert "i % 2" not in src
        assert "sleep(6.0)" not in src

    def test_the_send_path_records_the_rate(self, tree):
        import ast
        fn = next(n for n in ast.walk(tree)
                  if isinstance(n, ast.FunctionDef)
                  and n.name == "send_otr_message")
        assert "_record_send_rate" in ast.unparse(fn)

    def test_the_error_command_checks_for_a_flood(self, tree):
        import ast
        assert any("_note_possible_flood" in ast.unparse(n)
                   for n in ast.walk(tree)
                   if isinstance(n, ast.FunctionDef)
                   and n.name == "handle_message")

    def test_the_join_echo_learns_the_prefix(self, tree):
        import ast
        assert any("_own_prefix = prefix" in ast.unparse(n)
                   for n in ast.walk(tree)
                   if isinstance(n, ast.FunctionDef)
                   and n.name == "handle_message")


class TestTheFragmentCountStillLeaksWhichMessageItIs:
    """The fragmenter's docstring claimed every multi-fragment message was
    padded to a uniform count so an observer could not tell DAKE1 from DAKE3
    by counting lines. No such padding exists and no MIN_FRAGMENTS constant
    does either -- it described an intention.

    The claim is now removed rather than the padding added: padding every
    message to 48 fragments would cost more than the pacing change saves.
    This test holds the honesty of the docstring, not a protection."""

    def test_there_is_no_min_fragments_constant(self):
        assert not hasattr(otr.OTRMessageFragmenter, "MIN_FRAGMENTS")

    def test_different_sizes_still_produce_different_counts(self):
        import base64
        F = otr.OTRMessageFragmenter
        small = "?OTRv4 " + base64.b64encode(b"\x00" * 4000).decode()
        large = "?OTRv4 " + base64.b64encode(b"\x00" * 12000).decode()
        assert len(F.fragment(small, max_line=380)) != \
            len(F.fragment(large, max_line=380))

    def test_the_docstring_no_longer_claims_otherwise(self):
        doc = otr.OTRMessageFragmenter.fragment.__doc__ or ""
        assert "MIN_FRAGMENTS" not in doc or "no MIN_FRAGMENTS" in doc
        assert "NOT anti-fingerprinting" in doc


class TestTheDisconnectSaysWhatWasHappening:
    """A session was lost mid-DAKE the day after the pacing changed, and the
    log said only "Server closed the connection". That distinguishes none of
    the causes -- a flood kill, a ping timeout, the SAM tunnel dying, the
    server restarting all look identical from here -- so the pacing could be
    neither blamed nor cleared.

    These four facts separate them, and none of them is sensitive: counts,
    seconds, a preset name, and a sanitised server string.
    """

    @pytest.fixture
    def reporter(self):
        c = Client()
        c._report_disconnect_context = \
            CLIENT._report_disconnect_context.__get__(c)
        c.last_ping = __import__("time").time()
        c._last_otr_sent = {}
        return c

    def test_a_server_error_is_quoted(self, reporter):
        import time
        reporter._last_server_error = (
            "Closing Link: TurbidBranch (Excess Flood)", time.time())
        reporter._report_disconnect_context()
        assert reporter.said("Excess Flood")

    def test_the_absence_of_an_error_is_itself_reported(self, reporter):
        """Most ircds send "Closing Link: ... (Excess Flood)" before a flood
        kill. Nothing arriving is evidence too, and the reader needs to be
        told that rather than left to infer it from silence."""
        reporter._report_disconnect_context()
        assert reporter.said("No ERROR line")

    def test_a_stale_error_is_not_quoted(self, reporter):
        """An ERROR from twenty minutes ago has nothing to do with this
        disconnect, and quoting it would point at the wrong cause."""
        import time
        reporter._last_server_error = ("Closing Link: (Excess Flood)",
                                       time.time() - 3600)
        reporter._report_disconnect_context()
        assert not reporter.said("Excess Flood")
        assert reporter.said("No ERROR line")

    def test_it_reports_how_long_the_server_was_silent(self, reporter):
        """A large number points at a ping timeout rather than a flood kill."""
        import time
        reporter.last_ping = time.time() - 240
        reporter._report_disconnect_context()
        assert reporter.said("since the last message from the server")

    def test_it_reports_how_long_since_we_sent(self, reporter):
        """A drop during or just after a burst points at the send rate. A
        drop while idle -- which is what actually happened -- does not."""
        import time
        reporter._last_otr_sent = {"LoneStyx": time.time() - 55}
        reporter._last_fragment_count = 17
        reporter._report_disconnect_context()
        assert reporter.said("since our last OTR message")
        assert reporter.said("17 fragments")

    def test_it_says_when_nothing_was_sent(self, reporter):
        reporter._report_disconnect_context()
        assert reporter.said("No OTR message sent")

    def test_it_names_the_pacing_in_force(self, reporter):
        """The setting under suspicion should not have to be remembered
        separately from the failure it is suspected of."""
        reporter._pace_preset = "fast"
        reporter._report_disconnect_context()
        assert reporter.said("pacing was 'fast'")

    def test_a_hostile_error_string_cannot_inject_escapes(self, reporter):
        import time
        reporter._last_server_error = ("bye \x1b[2Jgone", time.time())
        reporter._report_disconnect_context()
        assert "\x1b[2J" not in "".join(reporter.lines)

    def test_it_survives_a_client_with_nothing_recorded(self, reporter):
        del reporter.last_ping
        del reporter._last_otr_sent
        reporter._report_disconnect_context()
        assert reporter.lines

    def test_the_recv_loop_calls_it(self):
        import ast
        import os
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(root, "otrv4+.py"), encoding="utf-8") as fh:
            tree = ast.parse(fh.read())
        fn = next(n for n in ast.walk(tree)
                  if isinstance(n, ast.FunctionDef) and n.name == "_recv_loop")
        assert "_report_disconnect_context" in ast.unparse(fn)

    def test_the_error_handler_records_the_reason_for_it(self):
        import ast
        import os
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(root, "otrv4+.py"), encoding="utf-8") as fh:
            tree = ast.parse(fh.read())
        assert any("_last_server_error" in ast.unparse(n)
                   for n in ast.walk(tree)
                   if isinstance(n, ast.FunctionDef)
                   and n.name == "handle_message")


class TestTheRecvThreadHazardIsRecorded:
    """A responder's DAKE2 is sent from the receive thread, which is inside
    time.sleep() for the duration and cannot answer a server PING. Not fixed
    in this release -- it did not cause the disconnect being investigated,
    and fixing it moves the handshake display onto completion callbacks the
    day after it first worked. Asserted as documented so it cannot be
    forgotten rather than asserted as solved."""

    def test_the_hazard_is_written_down_where_it_lives(self):
        import ast
        import os
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(root, "otrv4+.py"), encoding="utf-8") as fh:
            tree = ast.parse(fh.read())
        fn = next(n for n in ast.walk(tree)
                  if isinstance(n, ast.FunctionDef)
                  and n.name == "_route_otr_to_session_manager")
        doc = ast.get_docstring(fn) or ""
        assert "KNOWN HAZARD" in doc
        assert "receive thread" in doc

    def test_the_smp_path_still_offloads(self):
        """The same disease was fixed there. If that offload is ever removed,
        both paths block and the stacking gets much worse."""
        import ast
        import os
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(root, "otrv4+.py"), encoding="utf-8") as fh:
            src = fh.read()
        assert "_smp_executor" in src


class TestAPeerKilledForFloodingIsEvidenceAboutUs:
    """Observed on irc.postman.i2p at a fast preset:

        ⚠ LucidDusk disconnected: Excess Flood - OTR session ended

    The server killed the PEER, mid-SMP2. This client carried on at the same
    rate having learned nothing, because only an ERROR addressed to us
    counted as evidence.

    Both ends run this client at whatever preset the pair agreed, and the
    messages are symmetrical -- SMP2 and SMP3 are 47 fragments each. If their
    SMP2 was too fast for this server, our SMP3 was about to be. The peer's
    kill is the cheapest warning available: it arrives before ours.
    """

    @pytest.fixture
    def client(self):
        c = Client()
        c._note_peer_flood = CLIENT._note_peer_flood.__get__(c)
        return c

    @pytest.mark.parametrize("reason", [
        "Excess Flood",
        "Closing Link: LucidDusk[i2p] (Excess Flood)",
        "Max SendQ exceeded",
        "Killed (flooding)",
    ])
    def test_a_peer_flood_kill_drops_our_rate(self, client, reason):
        client._pace_preset = "turbo"
        assert client._note_peer_flood("LucidDusk", reason) is True
        assert client._pace_name() == "safe"

    def test_it_explains_why_a_working_session_slowed_down(self, client):
        client._pace_preset = "fast"
        client._note_peer_flood("LucidDusk", "Excess Flood")
        assert client.said("was disconnected by the server for flooding")
        assert client.said("same fragment rate")

    def test_an_ordinary_quit_changes_nothing(self, client):
        client._pace_preset = "fast"
        assert client._note_peer_flood("LucidDusk", "Leaving") is False
        assert client._pace_name() == "fast"

    def test_a_quit_with_no_reason_changes_nothing(self, client):
        client._pace_preset = "fast"
        assert client._note_peer_flood("LucidDusk", "") is False
        assert client._pace_name() == "fast"

    def test_it_says_nothing_when_already_safe(self, client):
        client._note_peer_flood("LucidDusk", "Excess Flood")
        assert not client.said("was disconnected by the server")

    def test_a_hostile_quit_message_can_only_slow_us_down(self, client):
        """The reason is attacker-controlled -- a peer can /quit with any
        text. Acting on it is safe precisely because the only reachable
        outcome is a more conservative rate, and nothing ever raises it
        automatically."""
        client._pace_preset = "turbo"
        client._note_peer_flood("Mallory", "Excess Flood")
        assert client._pace_name() == "safe"
        for _ in range(10):
            client._note_peer_flood("Mallory", "definitely not a flood")
        assert client._pace_name() == "safe"

    def test_a_hostile_peer_name_cannot_inject_escapes(self, client):
        client._pace_preset = "fast"
        client._note_peer_flood("evil\x1b[2Jnick", "Excess Flood")
        assert "\x1b[2J" not in "".join(client.lines)

    def test_the_disconnect_handler_calls_it(self):
        import ast
        import os
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(root, "otrv4+.py"), encoding="utf-8") as fh:
            tree = ast.parse(fh.read())
        fn = next(n for n in ast.walk(tree)
                  if isinstance(n, ast.FunctionDef)
                  and n.name == "_on_peer_disconnected")
        assert "_note_peer_flood" in ast.unparse(fn)

    def test_the_quit_reason_is_sanitised_before_display(self):
        """It reaches the terminal, and it is server- or peer-supplied."""
        import ast
        import os
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(root, "otrv4+.py"), encoding="utf-8") as fh:
            tree = ast.parse(fh.read())
        fn = next(n for n in ast.walk(tree)
                  if isinstance(n, ast.FunctionDef)
                  and n.name == "_on_peer_disconnected")
        assert "_sanitise(reason, 160)" in ast.unparse(fn)


class TestTheReportNamesTheRateThatCausedIt:
    """From the handset that was actually killed:

        18:52:57 [sys] The server complained about the send rate - fragment
                       pacing dropped to 'safe' for this session.
        18:52:57 [sys] Server: Closing Link: LucidDusk[...] (Excess Flood)
        18:52:58 [sys] Server closed the connection...
        18:52:58 [sys]    43s since our last OTR message (46 fragments).
        18:52:58 [sys]    Fragment pacing was 'safe'.

    It was not 'safe'. 34 of those 46 fragments went out in 33 seconds, which
    is 'fast'. `_note_possible_flood` had already retreated to 'safe' one
    second earlier, and the report read the live value -- so on the one path
    where the answer matters most, it named the retreat instead of the cause.
    """

    @pytest.fixture
    def reporter(self):
        c = Client()
        c._report_disconnect_context = \
            CLIENT._report_disconnect_context.__get__(c)
        c.last_ping = __import__("time").time()
        c._last_otr_sent = {"IvoryDelta": __import__("time").time() - 43}
        c._last_fragment_count = 46
        return c

    def test_it_names_the_preset_the_send_used(self, reporter):
        reporter._last_send_preset = "fast"
        reporter._pace_preset = "safe"          # the backoff already fired
        reporter._report_disconnect_context()
        assert reporter.said("was 'fast' for that send")

    def test_it_also_says_what_the_rate_is_now(self, reporter):
        """Both, because the user needs to know the retreat happened as well
        as what caused it."""
        reporter._last_send_preset = "fast"
        reporter._pace_preset = "safe"
        reporter._report_disconnect_context()
        assert reporter.said("is 'safe' now")

    def test_one_value_when_nothing_changed(self, reporter):
        reporter._last_send_preset = "safe"
        reporter._pace_preset = "safe"
        reporter._report_disconnect_context()
        assert reporter.said("Fragment pacing was 'safe'.")
        assert not reporter.said("for that send")

    def test_it_falls_back_to_the_live_value(self, reporter):
        """No send recorded yet -- there is nothing better to report."""
        reporter._pace_preset = "normal"
        reporter._report_disconnect_context()
        assert reporter.said("Fragment pacing was 'normal'")

    def test_the_send_path_records_the_preset(self):
        import ast
        import os
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(root, "otrv4+.py"), encoding="utf-8") as fh:
            tree = ast.parse(fh.read())
        fn = next(n for n in ast.walk(tree)
                  if isinstance(n, ast.FunctionDef)
                  and n.name == "send_otr_message")
        assert "_last_send_preset = self._pace_name()" in ast.unparse(fn)

    def test_it_is_recorded_before_the_fragments_go_out(self):
        """After the loop it would be the post-backoff value again, because
        the ERROR can arrive while the send is still running."""
        import ast
        import os
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(root, "otrv4+.py"), encoding="utf-8") as fh:
            tree = ast.parse(fh.read())
        fn = next(n for n in ast.walk(tree)
                  if isinstance(n, ast.FunctionDef)
                  and n.name == "send_otr_message")
        src = ast.unparse(fn)
        assert src.index("_last_send_preset") < src.index("_pace.wait()")


class TestTheReconnectDoesNotContradictItself:
    """A handset printed, two lines apart, about one session:

        🔐 1 OTR session(s) kept through the reconnect - identity keys and
           pinned fingerprints unchanged.
        ⚠ OTR sessions lost on reconnect - /otr IvoryDelta

    The second was left over from when `_try_reconnect` really did clear the
    sessions. Of the two it was the wrong one, and it is the one that tells
    the user to throw away a working session and spend four minutes
    rebuilding it.
    """

    @staticmethod
    @pytest.fixture(scope="class")
    def auto_join_src():
        import ast
        import os
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(root, "otrv4+.py"), encoding="utf-8") as fh:
            tree = ast.parse(fh.read())
        fn = next(n for n in ast.walk(tree)
                  if isinstance(n, ast.FunctionDef)
                  and n.name == "auto_join_channel")
        return ast.unparse(fn)

    def test_a_surviving_session_is_not_listed_as_lost(self, auto_join_src):
        assert "has_session" in auto_join_src, (
            "every peer panel with history is still being reported as a lost "
            "session, whether or not the session survived")

    def test_the_claim_is_no_longer_that_sessions_were_lost(self, auto_join_src):
        assert "OTR sessions lost on reconnect" not in auto_join_src

    def test_it_still_reports_peers_with_no_session(self, auto_join_src):
        """The message is worth keeping for the case it was written for."""
        assert "/otr " in auto_join_src

    def test_it_reports_alongside_the_preserved_notice(self, auto_join_src):
        """Both come from the same place, so they cannot drift apart again."""
        assert "_report_preserved_sessions" in auto_join_src
        assert auto_join_src.index("_report_preserved_sessions") < \
            auto_join_src.index("has_session")
