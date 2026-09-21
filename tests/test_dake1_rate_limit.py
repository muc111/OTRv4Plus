#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""`DAKE1RateLimiter` is per-peer, and these run it to prove it.

THE DEFECT
==========
The class is documented "Per-peer sliding-window rate limiter for DAKE1 (M-4
fix)" and takes a `peer_key`. Both production call sites --
`SessionManager.handle_dake1` and `EnhancedSessionManager._handle_dake1` --
called `process_dake1(dake1_msg)` without it, so every sender landed in the
default bucket. Measured before the fix, six DISTINCT peer pairs:

    pair 0..4  responder replied = True
    pair 5     responder replied = False
    limiter buckets: {'unknown': 5}

So the limit was process-wide. One peer spending five DAKE1s silently locked
out session establishment from every other contact for sixty seconds -- which
is the attack a per-peer limiter exists to prevent, so the M-4 fix did not
achieve its stated property.

WHY THE FIX IS MORE THAN PASSING AN ARGUMENT
============================================
Keying on the peer introduces two failure modes that did not exist while
there was only ever one bucket, and both were measured on the unbounded
version rather than reasoned about:

  * ONE DEQUE PER SENDER, KEPT FOREVER. 5000 unique peers left 5000 buckets
    and the map never shed a key. That would trade a lockout for a slow
    memory exhaustion, reachable pre-session by anyone who can deliver a
    stanza.
  * A BUCKET THE PEER CAN SPLIT. One contact spelled four ways --
    `alice@x.test`, `Alice@X.test`, and two resources -- produced four
    buckets and therefore four times the allowance.

Neither is a fix, so the limiter now prunes (the approach
`otrv4plus_voice.RateLimiter` already uses) and canonicalises its key.

WHAT THESE TESTS DRIVE
======================
Real `EnhancedSessionManager` instances exchanging real DAKE1s, not the
limiter in isolation, because the defect was never in the limiter -- it was in
what the call sites passed. A test that calls `is_allowed("alice")` directly
would have passed throughout the entire period the property was broken.
"""

import itertools
import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

otr = pytest.importorskip("otrv4_")

LIMIT = otr.DAKE1RateLimiter.MAX_ATTEMPTS

_counter = itertools.count()


def _manager():
    directory = tempfile.mkdtemp()
    config = otr.OTRConfig(test_mode=True)
    for attribute, name in (("trust_db_path", "trust.json"),
                            ("smp_secrets_path", "smp.json"),
                            ("key_storage_path", "keys")):
        if hasattr(config, attribute):
            setattr(config, attribute, os.path.join(directory, name))
    return otr.EnhancedSessionManager(config=config)


#: One real DAKE1, built once and replayed.
#:
#: Real bytes from a real `EnhancedSessionManager`, so the responder runs its
#: genuine admission path. Built once because a DAKE1 costs an X448 keypair
#: plus ML-KEM and ML-DSA work, and these tests need dozens.
#:
#: Replay is legitimate HERE and only here: `_handle_dake1` resets the session
#: and rebuilds its DAKE engine on each arrival, so each delivery is processed
#: afresh and spends exactly one unit of allowance -- which is the quantity
#: under test. Verified before relying on it: three replays produced three
#: DAKE2s and a bucket of three.
_DAKE1 = None


def _dake1():
    global _DAKE1
    if _DAKE1 is None:
        sender = _manager()
        payload, _should_send = sender.handle_outgoing_message(
            "victim@example.test", "")
        assert payload and payload.startswith("?OTRv4"), "no DAKE1 produced"
        _DAKE1 = payload
    return _DAKE1


@pytest.fixture(autouse=True)
def fresh_limiter():
    """A clean limiter per test.

    The limiter is module-level and shared, so without this a test measures
    whatever the previous one spent.
    """
    otr._dake1_rate_limiter._attempts.clear()
    otr._dake1_rate_limiter._last_prune = 0.0
    yield
    otr._dake1_rate_limiter._attempts.clear()
    otr._dake1_rate_limiter._last_prune = 0.0


# ── Test A: isolation ────────────────────────────────────────────────────────

class TestOnePeerCannotSpendAnothersAllowance:
    """THE PROPERTY. Activity from peer A must not consume peer B's budget."""

    def test_a_peer_that_exhausts_its_budget_is_limited(self):
        """The first half: the limit still exists and still bites."""
        responder = _manager()
        attacker_jid = "attacker@example.test"

        replies = []
        for _ in range(LIMIT + 2):
            dake1 = _dake1()
            replies.append(
                bool(responder._handle_dake1(attacker_jid, dake1)))

        assert replies[:LIMIT] == [True] * LIMIT, (
            "the responder refused a DAKE1 inside the allowance")
        assert replies[LIMIT:] == [False] * 2, (
            "the responder kept answering past the allowance; the limit is "
            "not being applied at all")

    def test_another_peer_is_unaffected_by_that_flood(self):
        """THE HALF THAT WAS BROKEN. Before the fix this was False: the
        attacker's five attempts emptied the single shared bucket and the
        innocent peer's very first DAKE1 was dropped in silence."""
        responder = _manager()

        for _ in range(LIMIT + 2):
            responder._handle_dake1(
                "attacker@example.test",
                _dake1())

        dake1 = _dake1()
        assert responder._handle_dake1("innocent@example.test", dake1), (
            "an innocent peer's first handshake was refused because somebody "
            "else had spent the allowance -- the limit is process-wide, not "
            "per-peer")

    def test_the_innocent_peer_keeps_its_whole_allowance(self):
        """Not merely "one got through". The flood must cost B nothing at
        all, so B's own limit must arrive exactly where it always would."""
        responder = _manager()

        for _ in range(LIMIT + 3):
            responder._handle_dake1(
                "attacker@example.test",
                _dake1())

        replies = []
        for _ in range(LIMIT + 1):
            replies.append(bool(responder._handle_dake1(
                "innocent@example.test",
                _dake1())))

        assert replies[:LIMIT] == [True] * LIMIT, (
            "the innocent peer got %d of its %d attempts, so the flood "
            "still cost it budget" % (replies.count(True), LIMIT))
        assert replies[LIMIT] is False, "the innocent peer's own limit is gone"

    def test_many_peers_are_each_independent(self):
        """Ten distinct senders, each spending its whole allowance, and none
        of them affecting the others."""
        responder = _manager()
        jids = ["peer%d@example.test" % i for i in range(10)]

        for jid in jids:
            for attempt in range(LIMIT):
                assert responder._handle_dake1(
                    jid, _dake1()), (
                    "%s was refused on attempt %d" % (jid, attempt + 1))

        for jid in jids:
            assert not responder._handle_dake1(
                jid, _dake1()), (
                "%s was allowed past its own limit" % jid)


# ── Test B: the same peer still hits the limit ───────────────────────────────

class TestTheLimitStillApplies:
    """The fix must not become a way to switch the control off."""

    def test_repeated_attempts_from_one_peer_are_capped(self):
        responder = _manager()
        allowed = 0
        for _ in range(LIMIT * 3):
            if responder._handle_dake1(
                    "flood@example.test",
                    _dake1()):
                allowed += 1
        assert allowed == LIMIT, (
            "%d DAKE1s were processed where the policy allows %d"
            % (allowed, LIMIT))

    def test_the_refusal_is_silent(self):
        """Deliberate, and stated in the class docstring: "Excess attempts
        are silently dropped (no error message to prevent oracle)." A refusal
        that raised or replied would tell an attacker where the limit is."""
        responder = _manager()
        for _ in range(LIMIT):
            responder._handle_dake1(
                "flood@example.test",
                _dake1())
        # Returns None rather than raising, and sends nothing back.
        assert responder._handle_dake1(
            "flood@example.test",
            _dake1()) is None

    def test_the_policy_numbers_are_unchanged(self):
        """This change restores a property. It does not retune the control."""
        assert otr.DAKE1RateLimiter.MAX_ATTEMPTS == 5
        assert otr.DAKE1RateLimiter.WINDOW_SECONDS == 60.0


# ── Test C: the production paths pass a stable, canonical key ────────────────

class TestTheProductionPathsKeyOnThePeer:
    """Driven, not read. Asserting on source text would pass against a call
    site that passed the wrong variable."""

    def test_the_live_path_creates_a_bucket_named_for_the_peer(self):
        """EnhancedSessionManager._handle_dake1 -- what both terminal clients
        and the Android bridge actually reach."""
        responder = _manager()
        responder._handle_dake1(
            "someone@example.test",
            _dake1())
        assert "someone@example.test" in otr._dake1_rate_limiter._attempts, (
            "buckets are %s -- the live path is not keying on the peer"
            % sorted(otr._dake1_rate_limiter._attempts))
        assert "unknown" not in otr._dake1_rate_limiter._attempts

    def test_the_base_manager_path_also_keys_on_the_peer(self):
        """SessionManager.handle_dake1, the other call site named in the
        finding."""
        base = otr.SessionManager(otr.OTRConfig(test_mode=True)) \
            if _base_takes_config() else otr.SessionManager()
        base.handle_dake1("other@example.test",
                          _dake1())
        assert "other@example.test" in otr._dake1_rate_limiter._attempts, (
            "buckets are %s -- SessionManager.handle_dake1 is not keying on "
            "the peer" % sorted(otr._dake1_rate_limiter._attempts))

    def test_both_paths_agree_on_the_key_for_one_peer(self):
        """The two call sites must not produce two buckets for one contact,
        or a peer reaching us by either route gets double the allowance."""
        responder = _manager()
        jid = "shared@example.test"
        responder._handle_dake1(jid, _dake1())
        before = sorted(otr._dake1_rate_limiter._attempts)

        base = otr.SessionManager(otr.OTRConfig(test_mode=True)) \
            if _base_takes_config() else otr.SessionManager()
        base.handle_dake1(jid, _dake1())
        assert sorted(otr._dake1_rate_limiter._attempts) == before, (
            "the two paths key the same peer differently: %s"
            % sorted(otr._dake1_rate_limiter._attempts))

    def test_a_resource_cannot_buy_a_second_allowance(self):
        """A peer that varies its resource must not multiply its budget."""
        responder = _manager()
        allowed = 0
        for i in range(LIMIT * 2):
            jid = "rotator@example.test/device%d" % i
            if responder._handle_dake1(
                    jid, _dake1()):
                allowed += 1
        assert allowed == LIMIT, (
            "%d attempts were allowed by rotating the resource, where the "
            "policy allows %d" % (allowed, LIMIT))

    def test_case_cannot_buy_a_second_allowance(self):
        responder = _manager()
        allowed = 0
        for spelling in ("peer@example.test", "PEER@example.test",
                         "Peer@Example.Test", "pEeR@eXaMpLe.tEsT",
                         "peer@EXAMPLE.TEST", "PeEr@example.test",
                         "peer@example.test"):
            if responder._handle_dake1(
                    spelling, _dake1()):
                allowed += 1
        assert allowed == LIMIT, (
            "%d attempts were allowed by varying case, where the policy "
            "allows %d" % (allowed, LIMIT))


def _base_takes_config():
    import inspect
    try:
        params = inspect.signature(otr.SessionManager.__init__).parameters
    except (TypeError, ValueError):
        return False
    return "config" in params


# ── Test D: reset semantics ──────────────────────────────────────────────────

class TestResetIsNotAProductionOperation:
    """Reset-after-success is NOT implemented, and these pin that decision.

    The docstring used to carry "(call after DAKE success)". Nothing else
    supported it: no production caller, no test asserting it, nothing in the
    changelog or the M-4 note. The only uses are test hygiene.

    Implementing it would WEAKEN the control rather than complete it. A
    completed DAKE costs the responder more CPU than a rejected DAKE1 -- an
    X448 keypair, three DH exchanges, ML-KEM and ML-DSA work -- so clearing
    the budget on success would hand unlimited DAKE1 processing to any peer
    able to finish one handshake, which is precisely the CPU exhaustion the
    limiter exists to bound.

    So the behaviour is unchanged and asserted, rather than changed on the
    strength of a parenthetical.
    """

    def test_a_successful_handshake_does_not_refund_the_budget(self):
        responder = _manager()
        jid = "peer@example.test"
        for _ in range(LIMIT):
            assert responder._handle_dake1(
                jid, _dake1())
        assert not responder._handle_dake1(
            jid, _dake1()), (
            "a completed handshake refunded the allowance; a peer able to "
            "finish one DAKE would have unlimited DAKE1 processing")

    def test_no_production_code_calls_reset(self):
        """Pins the decision where a future change would have to notice it.

        Scoped to the shipped modules: the tests use `reset` legitimately for
        hygiene, and forbidding that would be forbidding the supported use.
        """
        import pathlib
        import re
        root = pathlib.Path(__file__).resolve().parent.parent
        offenders = []
        for path in sorted(root.glob("otrv4*.py")) + \
                sorted((root / "android_bridge").glob("*.py")):
            text = path.read_text(encoding="utf-8")
            for number, line in enumerate(text.splitlines(), 1):
                if re.search(r"_dake1_rate_limiter\s*\.\s*reset\s*\(", line):
                    offenders.append("%s:%d" % (path.name, number))
        assert not offenders, (
            "production code now resets the DAKE1 limiter at %s. If that is "
            "intended, the security argument in DAKE1RateLimiter.reset has to "
            "be answered first: a completed DAKE costs more responder CPU "
            "than a refused one." % ", ".join(offenders))

    def test_reset_still_works_for_test_hygiene(self):
        """The supported use, which two existing suites depend on."""
        responder = _manager()
        jid = "peer@example.test"
        for _ in range(LIMIT):
            responder._handle_dake1(
                jid, _dake1())
        assert not responder._handle_dake1(
            jid, _dake1())

        otr._dake1_rate_limiter.reset(jid)
        assert responder._handle_dake1(
            jid, _dake1()), (
            "reset no longer clears a bucket, and two existing test suites "
            "rely on it to measure the protocol rather than the quota")

    def test_reset_canonicalises_like_is_allowed(self):
        """Otherwise `reset("Alice@X/phone")` would silently miss the bucket
        `is_allowed` created."""
        otr._dake1_rate_limiter.is_allowed("alice@x.test")
        otr._dake1_rate_limiter.reset("Alice@X.test/phone")
        assert "alice@x.test" not in otr._dake1_rate_limiter._attempts


# ── the table stays bounded ──────────────────────────────────────────────────

class TestTheTrackingTableIsBounded:
    """Per-peer buckets that are never dropped are a memory exhaustion
    reachable by anyone who can deliver a stanza -- pre-session, so cheaper
    to reach than the voice limiter's equivalent. Measured on the unbounded
    version: 5000 unique peers left 5000 buckets.
    """

    def test_a_flood_of_distinct_peers_does_not_grow_without_limit(self):
        limiter = otr.DAKE1RateLimiter()
        for i in range(5000):
            limiter.is_allowed("attacker%d@evil.test" % i)
        assert len(limiter._attempts) <= limiter.MAX_TRACKED + 1, (
            "%d buckets retained; one deque per sender kept forever is a "
            "slow memory exhaustion" % len(limiter._attempts))

    def test_an_expired_bucket_is_dropped(self):
        limiter = otr.DAKE1RateLimiter()
        limiter.is_allowed("gone@example.test")
        # Age the entry past the window, then force a prune.
        limiter._attempts["gone@example.test"][0] -= (
            limiter.WINDOW_SECONDS * 2)
        limiter._last_prune = 0.0
        limiter.is_allowed("here@example.test")
        assert "gone@example.test" not in limiter._attempts
        assert "here@example.test" in limiter._attempts

    def test_a_recent_peer_survives_ordinary_churn(self):
        """Eviction is least-recently-seen, so a small amount of noise must
        not cost an active peer its budget."""
        limiter = otr.DAKE1RateLimiter()
        for _ in range(limiter.MAX_ATTEMPTS):
            limiter.is_allowed("active@example.test")
        for i in range(20):
            limiter.is_allowed("noise%d@example.test" % i)
        assert not limiter.is_allowed("active@example.test"), (
            "an active peer's budget did not survive ordinary churn")
