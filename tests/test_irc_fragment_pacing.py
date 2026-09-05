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
               "_note_possible_flood", "_record_send_rate")

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

    def test_the_default_is_not_slower_than_the_old_behaviour(self):
        for n in (2, 5, 16, 24, 48):
            assert run_pacer(BASE.DEFAULT_PACE, n) <= self.old_i2p_pacing(n)

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
        client._note_possible_flood("Closing Link: x (Excess Flood)")
        assert client.said("complained about the send rate")

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
        assert client.said("Fragment pacing: normal")

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
