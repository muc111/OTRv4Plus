#!/usr/bin/env python3
"""INV-12: only cryptographic SMP verification authorises voice.

Trust and display state must never stand in for it.  Three things have been
tried and rejected as authorisation inputs, and each is named in
`_smp_verified`'s own docstring:

  * `client._smp_reported` -- populated by matching substrings like
    "SMP VERIFIED" in printed lines.  Peer-influenced text reaching a panel
    could insert an entry, so reading it here made a log string sufficient to
    unlock a call.
  * name-token heuristics on the engine's state string.  An earlier version
    treated "STATE_UPDATED" as success, which is a generic state-change
    notification and says nothing about the outcome.
  * session attributes named `*_complete`.  SMP completes on failure too;
    completion is not verification.

A matching TOFU pin authorises nothing either -- it is identity continuity,
not authentication.
"""

import ast
import inspect
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

V = pytest.importorskip("otrv4plus_voice")


def _src(obj):
    return inspect.getsource(obj)


def _code_of(obj):
    """Executable source of `obj`, with its docstring removed.

    These functions document the inputs they deliberately do NOT read, so a
    plain substring search over the source matches the explanation and fails
    forever.
    """
    import textwrap
    fn = ast.parse(textwrap.dedent(inspect.getsource(obj))).body[0]
    if (fn.body and isinstance(fn.body[0], ast.Expr)
            and isinstance(fn.body[0].value, ast.Constant)
            and isinstance(fn.body[0].value.value, str)):
        fn.body.pop(0)
    return ast.unparse(fn)


class _Client:
    """Just enough host for the policy checks; the engine answer is set per test."""

    def __init__(self, answer=(False, "NONE")):
        self.otr = object()
        self.answer = answer
        self._smp_reported = {PEER: True}      # display state says "verified"

    def _smp_query_fn(self, otr, peer):
        if isinstance(self.answer, Exception):
            raise self.answer
        return self.answer


PEER = "bob@example.org"


def _manager(answer):
    import asyncio
    loop = asyncio.new_event_loop()
    mgr = V.VoiceCallManager(_Client(answer), loop)
    return mgr, loop


class TestTheGateReadsTheEngineOnly:

    def test_smp_verified_consults_the_engine_query(self):
        src = _src(V.VoiceCallManager._smp_verified)
        assert "_smp_query" in src

    def test_it_does_not_read_display_state(self):
        code = _code_of(V.VoiceCallManager._smp_verified)
        for banned in ("_smp_reported", "_smp_display_hints", "STATE_UPDATED",
                       "_complete", "trust", "pinned"):
            assert banned not in code, (
                "%s is read by the voice authorisation gate" % banned)

    def test_an_exception_denies_rather_than_allows(self):
        mgr, loop = _manager(RuntimeError("engine went away"))
        try:
            assert mgr._smp_verified(PEER) is False, (
                "a failure to determine SMP state must not authorise a call")
        finally:
            mgr._call_control.shutdown()
            loop.close()

    def test_it_returns_a_real_bool(self):
        """A truthy object would let a non-empty status dict authorise."""
        for answer, want in (((True, "SUCCEEDED"), True),
                             ((1, "SUCCEEDED"), True),
                             ((0, "NONE"), False)):
            mgr, loop = _manager(answer)
            try:
                got = mgr._smp_verified(PEER)
                assert got is want, (answer, got)
            finally:
                mgr._call_control.shutdown()
                loop.close()

    def test_display_state_cannot_stand_in_for_the_engine(self):
        # The double's _smp_reported says verified; the engine says no.
        mgr, loop = _manager((False, "FAILED"))
        try:
            assert mgr._smp_verified(PEER) is False
        finally:
            mgr._call_control.shutdown()
            loop.close()


class TestBothCallDirectionsAreGated:
    """Run each direction with an encrypted but unverified peer."""

    @pytest.fixture
    def unverified(self, monkeypatch):
        mgr, loop = _manager((False, "NONE"))
        monkeypatch.setitem(V._HOST, "voice_available", lambda: (True, ""))
        monkeypatch.setattr(V, "kem_provider", lambda: None)
        mgr._otr_material = lambda peer: (b"b", "AA" * 64, "BB" * 64)
        mgr.signals = []
        mgr._signal = lambda peer, verb, fields=(): mgr.signals.append(
            (verb, tuple(fields))) or True
        yield mgr, loop
        mgr._call_control.shutdown()
        loop.close()

    def test_outbound_calls_check_it(self, unverified):
        mgr, loop = unverified
        assert loop.run_until_complete(mgr.start_call(PEER)) is False
        assert mgr.last_refusal == "unverified"

    def test_outbound_checks_before_deriving_anything(self, unverified):
        mgr, loop = unverified
        loop.run_until_complete(mgr.start_call(PEER))
        assert mgr.signals == [], "an INVITE left for an unverified peer"
        assert PEER not in mgr._calls, (
            "key material is derived before the authorisation check")
        assert PEER not in mgr._last_invite

    @staticmethod
    def _invite(mgr, loop):
        call_id = bytes(range(16))
        fields = (call_id.hex(), "A" * 516,
                  "11" * V.VoiceKeyExchange.PUB_LEN, "22" * V.MLKEM_EK_LEN)
        loop.run_until_complete(mgr._on_invite(PEER, fields))
        return call_id

    def test_inbound_invites_check_it(self, unverified):
        mgr, loop = unverified
        self._invite(mgr, loop)
        assert PEER not in mgr._calls

    def test_an_unverified_inbound_call_is_rejected_not_ignored(self,
                                                               unverified):
        mgr, loop = unverified
        call_id = self._invite(mgr, loop)
        assert mgr.signals == [("REJECT", (call_id.hex(), "unverified"))]


class TestTofuDoesNotAuthorise:

    def test_the_tofu_block_is_separate_from_the_smp_gate(self):
        xmpp = pytest.importorskip("otrv4plus_xmpp")
        code = _code_of(xmpp.OTRv4PlusXMPP._voice_blocked_by_tofu)
        assert "_smp_verified" not in code, (
            "the TOFU check and the SMP gate have been merged; a matching "
            "pin must not be able to stand in for verification")

    def test_tofu_can_only_block_never_permit(self):
        """Its name and its return say "refuse", not "allow"."""
        xmpp = pytest.importorskip("otrv4plus_xmpp")
        assert "blocked" in xmpp.OTRv4PlusXMPP._voice_blocked_by_tofu.__name__
        code = _code_of(xmpp.OTRv4PlusXMPP._voice_blocked_by_tofu)
        # Every call site treats True as "stop", so a path that returned
        # something truthy on success would silently invert the gate.
        assert "return True" in code and "return False" in code

    def test_the_call_commands_check_tofu_and_then_the_manager(self):
        """Two independent gates, in that order, and neither replaces the
        other: TOFU refuses a changed fingerprint, SMP authorises."""
        xmpp = pytest.importorskip("otrv4plus_xmpp")
        src = _src(xmpp.OTRv4PlusXMPP._dispatch_calls)
        i = src.index('lstrip == "/call"')
        window = src[i:i + 400]
        assert "_voice_blocked_by_tofu" in window
        assert "start_call" in window

    def test_the_docstring_still_says_which_one_authorises(self):
        xmpp = pytest.importorskip("otrv4plus_xmpp")
        src = _src(xmpp.OTRv4PlusXMPP._apply_tofu)
        assert "_smp_verified" in src and "authenticat" in src.lower(), (
            "the note explaining that a matching pin authorises nothing has "
            "been lost, and it is the thing that stops the next person "
            "wiring trust into the voice gate")
