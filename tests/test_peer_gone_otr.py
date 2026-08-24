"""An abandoned OTR session clears itself so /otr works when the peer returns.

A ratchet is shared state. When the peer's client exits, its half is gone and
ours is not, so the next /otr found a live session on our side only and the
DAKE it started went nowhere. start_otr already force-resets a stuck session,
but only after a failed attempt the user has to notice and interpret.

The hard part is the trigger. "The peer went offline" is the wrong one: over
I2P this client reconnects constantly, and our own stream dropping produces
exactly the same presence for every peer. Tearing down a verified session on
a blip would be far worse than the problem being fixed -- it would throw away
a DAKE and an SMP verification because a tunnel hiccuped. So the timer is
armed by absence and cancelled by any evidence to the contrary, including our
own reconnect.

The 33-minute live call that motivated this had ten disconnects and ten
recoveries. None of them may clear anything.
"""

import asyncio
import time
import types

import pytest

pytest.importorskip("slixmpp")
import otrv4plus_xmpp as xmpp


PEER = "alice@example.i2p"
OTHER = "carol@example.i2p"


class _FakeOTR:
    def __init__(self):
        self.ended = []

    def end_session(self, peer):
        self.ended.append(peer)


class _FakeVoice:
    def __init__(self, active=()):
        self._active = set(active)

    def has_active_call(self, peer):
        return peer in self._active


class _FakeClient:
    PEER_GONE_SECONDS = xmpp.OTRv4PlusXMPP.PEER_GONE_SECONDS

    _peer_is_alive = xmpp.OTRv4PlusXMPP._peer_is_alive
    _arm_peer_gone = xmpp.OTRv4PlusXMPP._arm_peer_gone
    _clear_peer_gone = xmpp.OTRv4PlusXMPP._clear_peer_gone
    _peer_in_call = xmpp.OTRv4PlusXMPP._peer_in_call
    _forget_otr = xmpp.OTRv4PlusXMPP._forget_otr

    def __init__(self, encrypted=(PEER,), in_call=()):
        self.otr = _FakeOTR()
        self._encrypted = set(encrypted)
        self._pending = {}
        self._last_dake1 = {}
        self._smp_reported = {(PEER, "SUCCEEDED"), (OTHER, "SUCCEEDED")}
        self._peer_gone_at = {}
        self._peer_gone_task = None
        self._shutting_down = False
        self._voice_manager = _FakeVoice(in_call)

    def _start_peer_gone_sweeper(self):
        pass                       # the sweeper is driven directly in tests


# ---------------------------------------------------------------------------
# arming and cancelling
# ---------------------------------------------------------------------------

class TestArming:

    def test_absence_arms_the_timer(self):
        c = _FakeClient()
        c._arm_peer_gone(PEER)
        assert PEER in c._peer_gone_at

    def test_a_peer_with_no_session_arms_nothing(self):
        c = _FakeClient(encrypted=())
        c._arm_peer_gone(PEER)
        assert c._peer_gone_at == {}

    def test_returning_cancels_it(self):
        c = _FakeClient()
        c._arm_peer_gone(PEER)
        c._peer_is_alive(PEER)
        assert c._peer_gone_at == {}

    def test_our_own_disconnect_cancels_every_timer(self):
        c = _FakeClient(encrypted=(PEER, OTHER))
        c._arm_peer_gone(PEER)
        c._arm_peer_gone(OTHER)
        c._clear_peer_gone("our transport dropped")
        assert c._peer_gone_at == {}

    def test_our_disconnect_handler_calls_it(self):
        # Ten disconnects in one live call; not one may clear a session.
        import inspect
        src = inspect.getsource(xmpp.OTRv4PlusXMPP._on_disconnected)
        assert "_clear_peer_gone" in src

    def test_presence_handlers_are_wired_both_ways(self):
        import inspect
        gone = inspect.getsource(xmpp.OTRv4PlusXMPP._on_presence_unavailable)
        back = inspect.getsource(xmpp.OTRv4PlusXMPP._on_presence_available)
        assert "_arm_peer_gone" in gone
        assert "_peer_is_alive" in back

    def test_an_inbound_message_counts_as_proof_of_life(self):
        import inspect
        src = inspect.getsource(xmpp.OTRv4PlusXMPP._on_message)
        assert "_peer_is_alive(peer)" in src
        assert src.index("_peer_is_alive") < src.index("_check_rate_limit")


# ---------------------------------------------------------------------------
# the teardown itself
# ---------------------------------------------------------------------------

class TestForget:

    def test_it_ends_the_engine_session(self):
        c = _FakeClient()
        c._forget_otr(PEER, "offline")
        assert c.otr.ended == [PEER]

    def test_it_clears_every_piece_of_per_session_state(self):
        c = _FakeClient()
        c._pending[PEER] = "smp_secret"
        c._last_dake1[PEER] = "?OTRv4..."
        c._forget_otr(PEER, "offline")
        assert PEER not in c._encrypted
        assert PEER not in c._pending
        assert PEER not in c._last_dake1
        assert not [k for k in c._smp_reported if k[0] == PEER]

    def test_it_leaves_other_peers_alone(self):
        c = _FakeClient(encrypted=(PEER, OTHER))
        c._forget_otr(PEER, "offline")
        assert OTHER in c._encrypted
        assert (OTHER, "SUCCEEDED") in c._smp_reported

    def test_it_does_not_forget_the_pinned_fingerprint(self):
        # Long-term identity is not session state. Forgetting it would turn
        # every reconnect into a fresh trust-on-first-use decision, which is
        # exactly where a MITM wants the user.
        import inspect
        src = inspect.getsource(xmpp.OTRv4PlusXMPP._forget_otr)
        for forbidden in ("untrust", "forget_fingerprint", "unpin",
                          "remove_fingerprint", "trust_db"):
            assert forbidden not in src

    def test_a_peer_with_nothing_to_clear_is_a_no_op(self):
        c = _FakeClient(encrypted=())
        c._forget_otr(PEER, "offline")
        assert c.otr.ended == []

    def test_an_engine_error_does_not_leave_stale_local_state(self):
        c = _FakeClient()

        def _boom(peer):
            raise RuntimeError("engine is unhappy")

        c.otr.end_session = _boom
        c._forget_otr(PEER, "offline")
        assert PEER not in c._encrypted


# ---------------------------------------------------------------------------
# the sweeper
# ---------------------------------------------------------------------------

def _sweep(client):
    """One pass of the production sweeper's decision, without the sleep."""
    now = time.monotonic()
    for peer, since in list(client._peer_gone_at.items()):
        if now - since < client.PEER_GONE_SECONDS:
            continue
        if client._peer_in_call(peer):
            client._peer_gone_at[peer] = now
            continue
        client._peer_gone_at.pop(peer, None)
        client._forget_otr(peer, "offline")


class TestSweeper:

    def test_a_recent_absence_is_left_alone(self):
        c = _FakeClient()
        c._arm_peer_gone(PEER)
        _sweep(c)
        assert PEER in c._encrypted
        assert PEER in c._peer_gone_at

    def test_a_long_absence_clears_the_session(self):
        c = _FakeClient()
        c._arm_peer_gone(PEER)
        c._peer_gone_at[PEER] -= c.PEER_GONE_SECONDS + 1
        _sweep(c)
        assert PEER not in c._encrypted
        assert c.otr.ended == [PEER]

    def test_a_live_call_is_never_torn_down(self):
        # Media does not use XMPP, so a call can be healthy while presence
        # says the peer is gone. Ending OTR would take rekey and END with it.
        c = _FakeClient(in_call=(PEER,))
        c._arm_peer_gone(PEER)
        c._peer_gone_at[PEER] -= c.PEER_GONE_SECONDS + 1
        _sweep(c)
        assert PEER in c._encrypted
        assert c.otr.ended == []

    def test_a_call_that_ends_lets_the_teardown_proceed(self):
        c = _FakeClient(in_call=(PEER,))
        c._arm_peer_gone(PEER)
        c._peer_gone_at[PEER] -= c.PEER_GONE_SECONDS + 1
        _sweep(c)                                   # deferred: still on a call
        c._voice_manager = _FakeVoice()             # call ended
        c._peer_gone_at[PEER] -= c.PEER_GONE_SECONDS + 1
        _sweep(c)
        assert PEER not in c._encrypted

    def test_the_production_sweeper_defers_on_a_call(self):
        import inspect
        src = inspect.getsource(xmpp.OTRv4PlusXMPP._peer_gone_sweeper)
        assert "_peer_in_call(peer)" in src
        assert src.index("_peer_in_call") < src.index("_forget_otr")

    def test_no_voice_manager_is_not_a_call(self):
        c = _FakeClient()
        c._voice_manager = None
        assert c._peer_in_call(PEER) is False

    def test_a_broken_voice_manager_does_not_block_the_sweep(self):
        c = _FakeClient()

        class _Broken:
            def has_active_call(self, peer):
                raise RuntimeError("no")

        c._voice_manager = _Broken()
        assert c._peer_in_call(PEER) is False


class TestShutdown:

    def test_cleanup_cancels_the_sweeper(self):
        import inspect
        src = inspect.getsource(xmpp.OTRv4PlusXMPP.cleanup)
        assert "_peer_gone_task" in src
        assert "_peer_gone_at.clear()" in src
