#!/usr/bin/env python3
"""INV-13: a rejected frame is counted by cause, not lumped into authfail.

Every media rejection used to increment `auth_fail` unless its exception text
happened to contain the word "replay":

    except FrameError as exc:
        if "replay" in str(exc): stats["replay"] += 1
        else:                    stats["auth_fail"] += 1

So `authfail=87` on a live call could equally mean a forged frame, a peer
that had rekeyed ahead of us, a frame from a retired epoch, or a byte stream
that had lost sync.  Only the first is an authentication failure, and the
second is what actually happened -- which took a 69-minute call to work out
because the number could not distinguish them.

Classifying a rejection does not soften it.  Every reason still discards the
frame; these tests check that too.
"""

import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

V = pytest.importorskip("otrv4plus_voice")
FrameError = V.FrameError


class TestReasonsAreDistinct:

    def test_every_reason_maps_to_its_own_counter(self):
        mapping = FrameError.STAT_FOR_REASON
        assert len(set(mapping.values())) == len(mapping), (
            "two reasons share a counter, so they cannot be told apart")

    def test_only_a_tag_failure_counts_as_authentication(self):
        assert FrameError.STAT_FOR_REASON[FrameError.AUTH] == "auth_fail"
        for reason, stat in FrameError.STAT_FOR_REASON.items():
            if reason != FrameError.AUTH:
                assert stat != "auth_fail", (
                    "%s is being counted as an authentication failure"
                    % reason)

    def test_every_counter_exists_in_the_stats_schema(self):
        for stat in FrameError.STAT_FOR_REASON.values():
            assert stat in V.MEDIA_STAT_KEYS, (
                "%s is not a declared counter, so it would KeyError at the "
                "moment something went wrong" % stat)

    def test_new_stats_start_at_zero(self):
        stats = V.new_media_stats()
        for stat in FrameError.STAT_FOR_REASON.values():
            assert stats[stat] == 0


class TestUnclassifiedIsNotAuthFail:

    def test_a_bare_frame_error_defaults_to_malformed(self):
        """A raise site that forgets to classify must not inflate authfail."""
        exc = FrameError("something went wrong")
        assert exc.reason == FrameError.MALFORMED
        assert FrameError.STAT_FOR_REASON[exc.reason] != "auth_fail"

    def test_the_reason_survives_being_raised(self):
        try:
            raise FrameError("no live key for epoch 4", FrameError.NO_KEY)
        except FrameError as exc:
            assert exc.reason == FrameError.NO_KEY

    def test_it_is_still_a_value_error(self):
        """Callers catch ValueError in places; the hierarchy must not move."""
        assert issubclass(FrameError, ValueError)


class TestTheRaiseSitesAreClassified:
    """Read the source: an unclassified raise is the regression."""

    def _src(self):
        return open(os.path.join(ROOT, "otrv4plus_voice.py"),
                    encoding="utf-8").read()

    def test_the_no_key_path_is_classified(self):
        src = self._src()
        assert 'FrameError("no live key for epoch %d" % epoch, FrameError.NO_KEY)' in src

    def test_the_tag_failure_is_classified_as_auth(self):
        src = self._src()
        i = src.index("except _INVALID_TAG:")
        window = src[i:i + 700]
        assert "FrameError.AUTH" in window, (
            "the AES-256-GCM tag failure is not classified as an "
            "authentication failure, which is the one thing it is")

    def test_the_replay_path_is_classified(self):
        assert "FrameError.REPLAY" in self._src()

    def test_the_receiver_does_not_match_on_message_text(self):
        src = self._src()
        assert 'if "replay" in text' not in src, (
            "the receiver is classifying by substring again; renaming an "
            "error message would silently reclassify every replay as an "
            "authentication failure")

    def test_the_receiver_dispatches_on_the_reason(self):
        src = self._src()
        assert "FrameError.STAT_FOR_REASON.get(" in src


class TestNothingIsAccepted:
    """Classification must not have become tolerance."""

    def _src(self):
        return open(os.path.join(ROOT, "otrv4plus_voice.py"),
                    encoding="utf-8").read()

    def test_every_reason_still_drops_the_frame(self):
        src = self._src()
        i = src.index("FrameError.STAT_FOR_REASON.get(")
        window = src[i:i + 400]
        assert 'self.stats["dropped"] += 1' in window, (
            "a classified rejection no longer counts as dropped, which "
            "would mean it was accepted")

    def test_no_reason_bypasses_the_aead(self):
        """The tag check must be unconditional."""
        src = self._src()
        i = src.index("except _INVALID_TAG:")
        window = src[i:i + 700]
        assert "return" not in window.split("raise")[0], (
            "a frame that failed its tag can reach a return")


class TestTheDiagnosticSaysWhich:

    def _src(self):
        return open(os.path.join(ROOT, "otrv4plus_voice.py"),
                    encoding="utf-8").read()

    def test_the_no_media_diagnosis_breaks_out_the_causes(self):
        src = self._src()
        i = src.index("datagrams are arriving but none authenticate")
        window = src[i:i + 600]
        for label in ("nokey=", "retired=", "malformed=", "authfail=",
                      "replay=", "foreign="):
            assert label in window, (
                "%s is missing from the diagnosis a user actually reads"
                % label)

    def test_the_in_call_telemetry_reports_no_key(self):
        """The counter that distinguishes rekey divergence from an attack."""
        src = self._src()
        assert 'delta.get("rej_no_key", 0)' in src
