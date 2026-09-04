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
        src = _src(V.VoiceCallManager._smp_verified)
        tail = src[src.rindex("except"):]
        assert "return False" in tail, (
            "a failure to determine SMP state must not authorise a call")

    def test_it_returns_a_real_bool(self):
        """A truthy object would let a non-empty status dict authorise."""
        src = _src(V.VoiceCallManager._smp_verified)
        assert "bool(" in src


class TestBothCallDirectionsAreGated:

    def test_outbound_calls_check_it(self):
        assert "_smp_verified" in _src(V.VoiceCallManager.start_call)

    def test_outbound_checks_before_deriving_anything(self):
        src = _src(V.VoiceCallManager.start_call)
        assert src.index("_smp_verified") < src.index("call_id"), (
            "key material is derived before the authorisation check")

    def test_inbound_invites_check_it(self):
        handler = None
        for name in dir(V.VoiceCallManager):
            if "invite" in name.lower():
                fn = getattr(V.VoiceCallManager, name, None)
                if fn is not None and callable(fn):
                    try:
                        if "_smp_verified" in _src(fn):
                            handler = name
                            break
                    except (OSError, TypeError):
                        continue
        assert handler, "no inbound call handler consults _smp_verified"

    def test_an_unverified_inbound_call_is_rejected_not_ignored(self):
        src = _src(V)
        i = src.index('if not self._smp_verified(peer):\n            self._signal')
        window = src[i:i + 400]
        assert '"REJECT"' in window
        assert "unverified" in window


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
        src = _src(xmpp.OTRv4PlusXMPP.dispatch_line)
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
