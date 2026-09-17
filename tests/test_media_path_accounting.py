# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""What the voice diagnostics are allowed to claim.

A 41-minute call reported `0.0% of audio delivered` while both people were
talking to each other, and `6 I2P hops` from a program that has never asked
the router how many hops it uses. Both were printed by format strings with no
way to test them, so neither had ever been wrong in a way anything noticed.

These tests execute the claims.
"""

import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import otrv4plus_mediapath as mp
from otrv4plus_mediapath import MediaCounters, Outage


# ── the rekey that produced 0.0% ─────────────────────────────────────────────

class TestARekeyIsNotAGap:
    """THE DEFECT. `JitterBuffer.sequence()` packs the rekey epoch into the
    top bits of the ordering key, so subtracting two keys is a frame count
    only within one epoch. Across a rekey the difference is 2**62, and the gap
    counter added it -- so one rekey reported a healthy call as 0.0%.
    """

    def test_an_epoch_change_adds_no_phantom_gaps(self):
        import otrv4plus_voice as voice

        jb = voice.JitterBuffer()
        for counter in range(5):
            jb.push(0, counter, b"\x00" * 960)
        for _ in range(5):
            jb.pop()
        # The rekey. The counter restarts at zero in the new epoch.
        for counter in range(5):
            jb.push(1, counter, b"\x00" * 960)
        for _ in range(5):
            jb.pop()

        assert jb.stats["gaps"] == 0, (
            "a rekey charged the call %d lost frames" % jb.stats["gaps"])
        assert jb.stats["queued"] == 10

    def test_a_real_gap_inside_one_epoch_is_still_counted(self):
        """The fix must not buy its correctness by counting nothing."""
        import otrv4plus_voice as voice

        jb = voice.JitterBuffer()
        for counter in (0, 1, 5):          # 2, 3 and 4 were lost
            jb.push(0, counter, b"\x00" * 960)
        for _ in range(3):
            jb.pop()
        assert jb.stats["gaps"] == 3

    def test_the_epoch_field_is_where_the_module_says_it_is(self):
        import otrv4plus_voice as voice

        assert voice.JitterBuffer.EPOCH_SHIFT == 62
        assert voice.JitterBuffer.epoch_of(
            voice.JitterBuffer.sequence(7, 12)) == 7
        assert voice.JitterBuffer.epoch_of(
            voice.JitterBuffer.sequence(0, 12)) == 0

    def test_two_keys_in_one_epoch_still_subtract_to_a_frame_count(self):
        import otrv4plus_voice as voice

        a = voice.JitterBuffer.sequence(3, 100)
        b = voice.JitterBuffer.sequence(3, 104)
        assert b - a == 4

    def test_across_an_epoch_they_do_not(self):
        """Stated as a test because it is the trap: the difference looks like
        a frame count and is about 4.6e18."""
        import otrv4plus_voice as voice

        a = voice.JitterBuffer.sequence(0, 100)
        b = voice.JitterBuffer.sequence(1, 0)
        assert b - a > 10 ** 18


# ── the hop claim ────────────────────────────────────────────────────────────

class TestTheHopNoteSaysOnlyWhatIsTrue:

    def test_this_build_does_not_configure_tunnel_length(self):
        """THE FINDING. `SESSION CREATE` carries no `inbound.length`, no
        `outbound.length` and no `i2cp.*` anywhere in this codebase, so the
        3-hop requirement is inherited from the router's configuration rather
        than asserted by the client."""
        assert mp.hops_are_configured() is False

    def test_the_source_really_has_no_tunnel_option(self):
        """Checked against the source, so the claim above cannot go stale if
        somebody adds the option and forgets to flip the flag."""
        import otrv4plus_voice as voice
        import inspect

        source = inspect.getsource(voice)
        for option in ("inbound.length", "outbound.length", "i2cp.",
                       "inbound.quantity"):
            assert option not in source, (
                "%s is set now -- hops_are_configured() must return True"
                % option)

    def test_the_note_does_not_claim_six_hops(self):
        """`6 I2P hops` reads as one six-hop path rather than two three-hop
        ones, which is a different and worse anonymity story than the
        architecture has."""
        note = mp.hop_note()
        assert "6" not in note

    def test_it_names_the_per_direction_architecture(self):
        note = mp.hop_note()
        assert str(mp.REQUIRED_HOPS) in note
        assert "each way" in note or "each direction" in note

    def test_it_says_where_the_number_came_from(self):
        """A diagnostic mentioning hops must say whether anything measured
        them. This build did not."""
        assert "default" in mp.hop_note()

    def test_the_required_hop_count_is_three(self):
        assert mp.REQUIRED_HOPS == 3


# ── counts, not percentages ──────────────────────────────────────────────────

class TestDeliveryIsReportedAsCounts:

    def test_it_reports_what_was_played(self):
        line = mp.delivery_line(MediaCounters(played=1990, received=2000))
        assert "1990 played" in line
        assert "2000 received" in line

    def test_it_never_says_a_percentage(self):
        line = mp.delivery_line(MediaCounters(played=1990, gaps=10))
        assert "%" not in line

    def test_a_counter_that_was_never_wired_prints_nothing(self):
        """Rather than a confident zero. §19: do not allow a metric to remain
        at zero because a counter was never wired."""
        line = mp.delivery_line(MediaCounters(played=100))
        assert "received" not in line
        assert "concealed" not in line

    def test_an_empty_call_says_so_rather_than_reporting_zeros(self):
        """A call that never started and a call that lost all its audio need
        different sentences; the old summary gave them the same one."""
        assert "no media counters" in mp.delivery_line(MediaCounters())

    def test_shedding_is_reported_separately_from_loss(self):
        """It IS audio the user did not hear -- it is simply not the
        network's doing."""
        line = mp.delivery_line(MediaCounters(played=1000, shed=330))
        assert "330 shed locally" in line
        assert "missing" not in line

    def test_concealment_and_gaps_are_distinguishable(self):
        line = mp.delivery_line(
            MediaCounters(played=100, gaps=5, concealed=3))
        assert "5 missing" in line
        assert "3 concealed" in line

    def test_underruns_are_reported(self):
        assert "2 underrun" in mp.delivery_line(
            MediaCounters(played=10, underruns=2))

    def test_the_counters_carry_every_pipeline_stage(self):
        """A gap between two adjacent counters localises a fault to one
        stage instead of to "the network"."""
        names = set(MediaCounters().as_dict())
        for stage in ("captured", "encoded", "encrypted", "sent",
                      "received", "decrypted", "queued", "played"):
            assert stage in names, stage


# ── a rebuild is not a recovery ──────────────────────────────────────────────

class TestRecoveryMeansMediaActuallyResumed:

    def test_an_outage_that_produced_frames_recovered(self):
        assert Outage(10.0, 25.0, rebuilt=True, resumed_frames=400).recovered

    def test_a_rebuild_with_no_frames_did_not(self):
        """§27: "media path recovered" must mean datagrams were received and
        processed again -- not that the state machine finished rebuilding."""
        assert Outage(10.0, 25.0, rebuilt=True,
                      resumed_frames=0).recovered is False

    def test_an_outage_still_running_has_not_recovered(self):
        assert Outage(10.0, None).recovered is False
        assert Outage(10.0, None).duration_s is None

    def test_the_duration_is_measured(self):
        assert Outage(10.0, 25.0).duration_s == 15.0

    def test_a_clock_that_went_backwards_does_not_give_a_negative_outage(self):
        assert Outage(25.0, 10.0).duration_s == 0.0

    def test_no_outages_is_not_a_recovery_claim(self):
        assert mp.recovery_verdict([])[0] == "none"
        assert mp.outage_line([]) == ""

    def test_every_outage_recovering_is_a_recovery(self):
        code, text = mp.recovery_verdict([
            Outage(10.0, 25.0, resumed_frames=400),
            Outage(60.0, 79.0, rebuilt=True, resumed_frames=300)])
        assert code == "recovered"
        assert "2 outage(s)" in text
        assert "1 path rebuild(s)" in text
        assert "longest 19s" in text

    def test_a_rebuild_that_produced_nothing_is_reported_as_failed(self):
        code, _ = mp.recovery_verdict([
            Outage(10.0, 25.0, rebuilt=True, resumed_frames=0)])
        assert code == "failed"

    def test_some_recovered_and_some_not_is_partial(self):
        code, _ = mp.recovery_verdict([
            Outage(10.0, 25.0, resumed_frames=400),
            Outage(60.0, 79.0, rebuilt=True, resumed_frames=0)])
        assert code == "partial"

    def test_the_observed_call_is_described_correctly(self):
        """The 41m51s call: two outages, ~15s and ~19s, one rebuild, audio
        audibly resumed both times."""
        code, text = mp.recovery_verdict([
            Outage(300.0, 315.0, resumed_frames=250),
            Outage(1800.0, 1819.0, rebuilt=True, resumed_frames=317)])
        assert code == "recovered"
        assert "longest 19s" in text


# ── the budget adds up ───────────────────────────────────────────────────────

class TestTheLatencyBudgetIsConsistent:

    def test_the_observed_call_adds_up(self):
        """706 + 190 + 52 = 948, and the call reported ~948ms."""
        assert mp.budget_is_consistent(948.0, 706.0, 190.0, 52.0)

    def test_a_component_reading_from_another_call_is_caught(self):
        """§19: do not allow stale values from a previous call."""
        assert mp.budget_is_consistent(948.0, 100.0, 190.0, 52.0) is False

    def test_an_unwired_counter_is_caught(self):
        assert mp.budget_is_consistent(948.0, 0.0, 0.0, 0.0) is False

    def test_small_disagreement_is_tolerated(self):
        """Each part is a median of a different sample window, so they are
        not required to sum exactly."""
        assert mp.budget_is_consistent(948.0, 706.0, 190.0, 20.0)

    def test_rubbish_does_not_raise(self):
        assert mp.budget_is_consistent(None, 1, 2, 3) is False


# ── it leaks nothing ─────────────────────────────────────────────────────────

class TestNothingIdentifyingCanReachTheDiagnostic:

    def test_the_hop_note_names_no_destination(self):
        note = mp.hop_note()
        assert ".i2p" not in note
        assert "b32" not in note

    def test_a_counters_repr_carries_counts_only(self):
        text = repr(MediaCounters(played=5, sent=7))
        assert "@" not in text and ".i2p" not in text

    def test_an_outage_repr_carries_no_endpoint(self):
        text = repr(Outage(1.0, 2.0, rebuilt=True, resumed_frames=1))
        assert "@" not in text and ".i2p" not in text

    def test_the_module_holds_no_cryptography_and_no_io(self):
        """Checked over CODE lines only.

        The docstrings explain the rekey defect at length, so a search of the
        whole source finds "key" in the prose describing why a rekey is not a
        gap -- which is the opposite of the thing being guarded against.
        """
        import inspect

        code = []
        for line in inspect.getsource(mp).splitlines():
            stripped = line.strip()
            if stripped.startswith("#") or stripped.startswith('"""'):
                continue
            code.append(line)
        source = "\n".join(code)
        for forbidden in ("socket", "open(", "hashlib", "hmac", "Cipher",
                          "secret"):
            assert forbidden not in source, forbidden

    def test_it_imports_nothing_it_cannot_run_without(self):
        import inspect

        for line in inspect.getsource(mp).splitlines():
            stripped = line.strip()
            if not stripped.startswith(("import ", "from ")):
                continue
            assert "otrv4plus_voice" not in stripped, stripped
            assert "socket" not in stripped, stripped
