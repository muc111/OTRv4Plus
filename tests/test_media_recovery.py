"""Authenticated media-endpoint recovery after a network transition.

A SAM datagram session is bound to a transient destination. When the local
network changes, the router's session can stop delivering and the only way
back is a NEW session -- which has a NEW destination the peer has never
heard of. Rebuilding locally and carrying on is therefore useless: the peer
keeps sending to an endpoint that no longer receives.

So recovery needs the peer to be told where we moved. That announcement rides
the XMPP control channel, and arriving over it proves nothing: the same
channel carries whatever the server, or a compromised account, puts there.
The tag is derived from the committed epoch root -- which exists only because
the hybrid X448 + ML-KEM agreement succeeded -- so producing one needs the
media secret, not access to the signalling path.

Everything that decides whether to act on an announcement is inside the tag:
call_id, epoch, sequence, the destination itself, and the direction. These
tests cover each of those bindings by breaking exactly one at a time.

Nothing cryptographic moves during recovery. Keys, epoch, replay windows and
call identity all survive; only the address changes. That is the whole reason
this is an announcement and not a rekey.
"""

import asyncio
import threading
import types

import pytest

import otrv4plus_voice as V


CALL_ID = bytes(range(16))
OTHER_CALL_ID = bytes(range(16, 32))
ROOT = bytes(range(32)) * (V.ROOT_LEN // 32)
DEST_OLD = "A" * 516
DEST_NEW = "B" * 516
DEST_THIRD = "C" * 516


def _real_dest(seed=b"\x01"):
    """A destination that survives i2p_public_destination()."""
    body = (seed * 384)[:384] + bytes([5]) + (4).to_bytes(2, "big") + b"cert"
    return V.i2p_b64encode(body)


DEST_A = _real_dest(b"\x01")
DEST_B = _real_dest(b"\x02")
DEST_C = _real_dest(b"\x03")


def _endpoint_session(is_initiator, call_id=CALL_ID, epoch=0,
                      peer_dest=DEST_A):
    """A session carrying the real key schedule and the real endpoint logic."""
    s = object.__new__(V.VoiceCallSession)
    s.call_id = call_id
    s.is_initiator = is_initiator
    s.state = V.CallState.ACTIVE
    s._key_lock = threading.RLock()
    s.schedule = V.VoiceKeySchedule(call_id, is_initiator)
    s.schedule.install_initial(ROOT)
    for _ in range(epoch):
        nxt = s.schedule.epoch + 1
        confirms = s.schedule.begin_rekey(nxt, bytes(V.ROOT_LEN))
        s.schedule.commit_rekey(nxt, s.schedule.expected_peer_confirm())
    s._peer_dest = peer_dest
    s._our_dest = DEST_B
    s._endpoint_seq_sent = 0
    s._endpoint_seq_seen = 0
    s._sam_session_id = "sess-1"
    s._dgram_send_header = None
    s._transport_mode = V.VOICE_TRANSPORT_DATAGRAM
    return s


def _announce(sender, receiver_view=None):
    """Build an announcement from `sender`, as the peer would receive it."""
    return sender.build_endpoint_announcement()


# ---------------------------------------------------------------------------
# 1. the happy path, both directions
# ---------------------------------------------------------------------------

class TestEndpointAdoption:

    def _pair(self):
        # Same call, same root, opposite roles: exactly what a live call has.
        initiator = _endpoint_session(True)
        responder = _endpoint_session(False)
        return initiator, responder

    def test_the_responder_adopts_the_initiators_new_endpoint(self):
        ini, res = self._pair()
        ini._our_dest = DEST_B
        epoch, seq, dest, tag = ini.build_endpoint_announcement()
        assert res.accept_endpoint(epoch, seq, dest, tag) == "ok"
        assert res._peer_dest == V.i2p_public_destination(DEST_B)

    def test_the_initiator_adopts_the_responders_new_endpoint(self):
        ini, res = self._pair()
        res._our_dest = DEST_C
        epoch, seq, dest, tag = res.build_endpoint_announcement()
        assert ini.accept_endpoint(epoch, seq, dest, tag) == "ok"
        assert ini._peer_dest == V.i2p_public_destination(DEST_C)

    def test_adoption_refreshes_the_send_header(self):
        ini, res = self._pair()
        ini._our_dest = DEST_B
        epoch, seq, dest, tag = ini.build_endpoint_announcement()
        res.accept_endpoint(epoch, seq, dest, tag)
        assert res._dgram_send_header is not None, (
            "the new destination never reached the send path")
        assert V.i2p_public_destination(DEST_B).encode() in \
            res._dgram_send_header

    def test_the_sequence_advances_on_every_announcement(self):
        ini, _res = self._pair()
        first = ini.build_endpoint_announcement()[1]
        second = ini.build_endpoint_announcement()[1]
        assert second == first + 1

    def test_nothing_cryptographic_moves(self):
        ini, res = self._pair()
        before = (res.schedule.epoch, res.schedule.rekeys_committed,
                  res.schedule.rekeys_failed)
        ini._our_dest = DEST_B
        epoch, seq, dest, tag = ini.build_endpoint_announcement()
        res.accept_endpoint(epoch, seq, dest, tag)
        assert (res.schedule.epoch, res.schedule.rekeys_committed,
                res.schedule.rekeys_failed) == before

    def test_recovery_works_at_a_later_epoch(self):
        ini = _endpoint_session(True, epoch=3)
        res = _endpoint_session(False, epoch=3)
        ini._our_dest = DEST_B
        epoch, seq, dest, tag = ini.build_endpoint_announcement()
        assert epoch == 3
        assert res.accept_endpoint(epoch, seq, dest, tag) == "ok"

    def test_a_second_move_is_adopted_too(self):
        ini, res = self._pair()
        for dest in (DEST_B, DEST_C):
            ini._our_dest = dest
            epoch, seq, d, tag = ini.build_endpoint_announcement()
            assert res.accept_endpoint(epoch, seq, d, tag) == "ok"
        assert res._peer_dest == V.i2p_public_destination(DEST_C)


# ---------------------------------------------------------------------------
# 2. every binding, broken one at a time
# ---------------------------------------------------------------------------

class TestAuthenticationBindings:

    def _sender_and_victim(self, **kw):
        return _endpoint_session(True, **kw), _endpoint_session(False, **kw)

    def test_a_forged_tag_is_refused(self):
        ini, res = self._sender_and_victim()
        ini._our_dest = DEST_B
        epoch, seq, dest, _tag = ini.build_endpoint_announcement()
        assert res.accept_endpoint(epoch, seq, dest,
                                   b"\x00" * V.CONFIRM_LEN) == \
            "authentication failed"
        assert res._peer_dest == DEST_A, "a forged tag moved the endpoint"

    def test_a_tag_from_another_call_is_refused(self):
        ini, res = self._sender_and_victim()
        other = _endpoint_session(True, call_id=OTHER_CALL_ID)
        other._our_dest = DEST_B
        epoch, seq, dest, tag = other.build_endpoint_announcement()
        assert res.accept_endpoint(epoch, seq, dest, tag) == \
            "authentication failed"

    def test_a_reflected_tag_is_refused(self):
        # Our own announcement, echoed back at us. The direction byte is what
        # stops it standing in for the peer's.
        ini, res = self._sender_and_victim()
        res._our_dest = DEST_C
        epoch, seq, dest, tag = res.build_endpoint_announcement()
        res._endpoint_seq_seen = 0
        assert res.accept_endpoint(epoch, seq, dest, tag) == \
            "authentication failed"

    def test_a_substituted_destination_is_refused(self):
        ini, res = self._sender_and_victim()
        ini._our_dest = DEST_B
        epoch, seq, _dest, tag = ini.build_endpoint_announcement()
        assert res.accept_endpoint(epoch, seq, DEST_C, tag) == \
            "authentication failed"
        assert res._peer_dest == DEST_A

    def test_an_edited_sequence_is_refused(self):
        ini, res = self._sender_and_victim()
        ini._our_dest = DEST_B
        epoch, seq, dest, tag = ini.build_endpoint_announcement()
        assert res.accept_endpoint(epoch, seq + 5, dest, tag) == \
            "authentication failed"

    def test_an_edited_epoch_is_refused(self):
        ini = _endpoint_session(True, epoch=2)
        res = _endpoint_session(False, epoch=2)
        ini._our_dest = DEST_B
        epoch, seq, dest, tag = ini.build_endpoint_announcement()
        assert res.accept_endpoint(epoch - 1, seq, dest, tag) != "ok"

    def test_an_announcement_from_a_stale_epoch_is_refused(self):
        # The peer rekeyed; an announcement tagged under the old root must not
        # be usable afterwards.
        ini = _endpoint_session(True, epoch=1)
        res = _endpoint_session(False, epoch=1)
        ini._our_dest = DEST_B
        epoch, seq, dest, tag = ini.build_endpoint_announcement()
        nxt = res.schedule.epoch + 1
        res.schedule.begin_rekey(nxt, bytes(V.ROOT_LEN))
        res.schedule.commit_rekey(nxt, res.schedule.expected_peer_confirm())
        assert res.accept_endpoint(epoch, seq, dest, tag) != "ok"
        assert res._peer_dest == DEST_A

    def test_a_different_root_cannot_produce_a_valid_tag(self):
        ini, res = self._sender_and_victim()
        attacker = _endpoint_session(True)
        attacker.schedule = V.VoiceKeySchedule(CALL_ID, True)
        attacker.schedule.install_initial(bytes(V.ROOT_LEN))
        attacker._our_dest = DEST_B
        epoch, seq, dest, tag = attacker.build_endpoint_announcement()
        assert res.accept_endpoint(epoch, seq, dest, tag) == \
            "authentication failed"

    def test_an_unparseable_destination_is_refused_before_the_tag(self):
        _ini, res = self._sender_and_victim()
        assert res.accept_endpoint(0, 1, "!!!not base64!!!",
                                   b"\x00" * V.CONFIRM_LEN) == \
            "unparseable destination"


# ---------------------------------------------------------------------------
# 3. replay, rollback and ordering
# ---------------------------------------------------------------------------

class TestFreshness:

    def _moved(self):
        ini, res = _endpoint_session(True), _endpoint_session(False)
        ini._our_dest = DEST_B
        msg = ini.build_endpoint_announcement()
        assert res.accept_endpoint(*msg) == "ok"
        return ini, res, msg

    def test_a_duplicate_announcement_is_refused(self):
        _ini, res, msg = self._moved()
        assert res.accept_endpoint(*msg).startswith("stale sequence")
        assert res._peer_dest == V.i2p_public_destination(DEST_B)

    def test_an_older_announcement_cannot_roll_the_endpoint_back(self):
        ini, res = _endpoint_session(True), _endpoint_session(False)
        ini._our_dest = DEST_B
        first = ini.build_endpoint_announcement()
        ini._our_dest = DEST_C
        second = ini.build_endpoint_announcement()
        assert res.accept_endpoint(*second) == "ok"
        assert res.accept_endpoint(*first).startswith("stale sequence")
        assert res._peer_dest == V.i2p_public_destination(DEST_C), (
            "an older announcement rolled the endpoint backwards")

    def test_reordered_announcements_settle_on_the_newest(self):
        ini, res = _endpoint_session(True), _endpoint_session(False)
        msgs = []
        for dest in (DEST_B, DEST_C):
            ini._our_dest = dest
            msgs.append(ini.build_endpoint_announcement())
        for msg in reversed(msgs):          # they overtook each other
            res.accept_endpoint(*msg)
        assert res._peer_dest == V.i2p_public_destination(DEST_C)

    def test_an_announcement_naming_the_current_endpoint_is_a_no_op(self):
        ini, res = _endpoint_session(True), _endpoint_session(False)
        ini._our_dest = res._peer_dest
        epoch, seq, dest, tag = ini.build_endpoint_announcement()
        assert res.accept_endpoint(epoch, seq, dest, tag) == \
            "endpoint unchanged"

    def test_sequences_do_not_leak_between_calls(self):
        first = _endpoint_session(False, call_id=CALL_ID)
        second = _endpoint_session(False, call_id=OTHER_CALL_ID)
        first._endpoint_seq_seen = 99
        assert second._endpoint_seq_seen == 0


# ---------------------------------------------------------------------------
# 4. call state
# ---------------------------------------------------------------------------

class TestCallState:

    @pytest.mark.parametrize("state", [
        V.CallState.RINGING, V.CallState.CONNECTING,
        V.CallState.KEY_CONFIRMING, V.CallState.MEDIA_CONNECTING,
        V.CallState.ENDING, V.CallState.ENDED,
    ])
    def test_only_an_active_call_adopts_an_endpoint(self, state):
        ini, res = _endpoint_session(True), _endpoint_session(False)
        ini._our_dest = DEST_B
        msg = ini.build_endpoint_announcement()
        res.state = state
        assert res.accept_endpoint(*msg) == "call is not active"
        assert res._peer_dest == DEST_A

    def test_an_ended_call_cannot_be_resurrected_by_an_endpoint(self):
        ini, res = _endpoint_session(True), _endpoint_session(False)
        ini._our_dest = DEST_B
        msg = ini.build_endpoint_announcement()
        res.state = V.CallState.ENDED
        res.accept_endpoint(*msg)
        assert res.state == V.CallState.ENDED


# ---------------------------------------------------------------------------
# 5. when recovery is even attempted
# ---------------------------------------------------------------------------

class _Stalled:
    _recovery_possible = V.VoiceCallSession._recovery_possible
    _request_recovery = V.VoiceCallSession._request_recovery
    _vlog = V.VoiceCallSession._vlog

    def __init__(self, mode=V.VOICE_TRANSPORT_DATAGRAM, arriving=False):
        self.state = V.CallState.ACTIVE
        self._transport_mode = mode
        self._recover_attempts = 0
        self._recovering = False
        self.peer = "alice@example.i2p"
        self.call_id = CALL_ID
        now = V.time.monotonic()
        self._rx_last_frame = now - 60
        self._rx_last_datagram = now if arriving else now - 60
        self.asked = []
        self.on_media_stalled = lambda p, c: self.asked.append((p, c))


class TestWhenRecoveryIsAttempted:

    def test_a_dead_datagram_path_is_recoverable(self):
        assert _Stalled()._recovery_possible() is True

    def test_a_path_that_is_delivering_is_not_rebuilt(self):
        # Datagrams arriving but not authenticating is not a transport
        # problem, and rebuilding would discard a working path for nothing.
        assert _Stalled(arriving=True)._recovery_possible() is False

    def test_the_stream_transport_has_no_endpoint_to_replace(self):
        assert _Stalled(mode=V.VOICE_TRANSPORT_STREAM)._recovery_possible() \
            is False

    def test_attempts_are_bounded(self):
        s = _Stalled()
        for _ in range(V.VOICE_RECOVER_ATTEMPTS):
            assert s._request_recovery() is True
            s._recovering = False
        assert s._request_recovery() is False, "unbounded rebuild attempts"

    def test_a_request_marks_the_session_recovering(self):
        s = _Stalled()
        s._request_recovery()
        assert s._recovering is True

    def test_only_an_active_call_is_recovered(self):
        s = _Stalled()
        s.state = V.CallState.ENDING
        assert s._recovery_possible() is False

    def test_no_callback_means_no_recovery(self):
        s = _Stalled()
        s.on_media_stalled = None
        assert s._request_recovery() is False
        assert s._recovering is False

    def test_a_failing_callback_does_not_leave_the_session_recovering(self):
        # Otherwise the watchdog's deadline would be suspended forever.
        s = _Stalled()

        def _boom(peer, call_id):
            raise RuntimeError("no loop")

        s.on_media_stalled = _boom
        assert s._request_recovery() is False
        assert s._recovering is False


# ---------------------------------------------------------------------------
# 6. the watchdog, with recovery in the loop
# ---------------------------------------------------------------------------

class _Watched:
    _rx_watchdog = V.VoiceCallSession._rx_watchdog
    _rx_idle_seconds = V.VoiceCallSession._rx_idle_seconds
    _rx_diagnosis = V.VoiceCallSession._rx_diagnosis
    _sam_control_state = V.VoiceCallSession._sam_control_state
    _signal_stream_lost = V.VoiceCallSession._signal_stream_lost
    _recovery_possible = V.VoiceCallSession._recovery_possible
    _request_recovery = V.VoiceCallSession._request_recovery
    _vlog = V.VoiceCallSession._vlog

    def __init__(self, mode=V.VOICE_TRANSPORT_DATAGRAM):
        self._running = True
        self.state = V.CallState.ACTIVE
        self._transport_mode = mode
        self.stats = V.new_media_stats()
        self._rx_degraded = False
        self._recovering = False
        self._recover_attempts = 0
        self._rx_authenticated = 0
        self._rx_mark = 0
        self._sam_control = None
        self._loss_signalled = False
        self._closing = False
        self.peer = "alice@example.i2p"
        self.call_id = CALL_ID
        self.lost = []
        self.asked = []
        self.on_stream_lost = lambda p, c, why: self.lost.append(why)
        self.on_media_stalled = lambda p, c: self.asked.append(c)
        self.loop = types.SimpleNamespace(
            call_soon_threadsafe=lambda cb, *a: cb(*a))
        now = V.time.monotonic()
        self._rx_last_frame = now
        self._rx_last_datagram = now

    def idle_for(self, seconds):
        base = V.time.monotonic() - seconds
        self._rx_last_frame = base
        self._rx_last_datagram = base


@pytest.fixture(autouse=True)
def _fast(monkeypatch):
    monkeypatch.setattr(V, "VOICE_RX_CHECK_S", 0.01)


async def _spin(session, rounds=8):
    task = asyncio.ensure_future(session._rx_watchdog())
    for _ in range(rounds):
        await asyncio.sleep(V.VOICE_RX_CHECK_S * 1.5)
        if task.done():
            break
    if not task.done():
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
    return task


def _run(coro, timeout=5.0):
    return asyncio.run(asyncio.wait_for(coro, timeout))


class TestWatchdogDrivesRecovery:

    def test_a_stalled_path_asks_for_recovery_before_being_declared_dead(self):
        async def _drive():
            s = _Watched()
            s.idle_for(V.VOICE_RX_DEAD_S + 1.0)
            await _spin(s, rounds=2)
            return s

        s = _run(_drive())
        assert s.asked, "the call was dropped without trying to recover it"
        assert s.lost == []

    def test_an_unrecoverable_path_is_still_declared_dead(self):
        async def _drive():
            s = _Watched(mode=V.VOICE_TRANSPORT_STREAM)
            s.idle_for(V.VOICE_RX_DEAD_S + 1.0)
            await _spin(s)
            return s

        s = _run(_drive())
        assert s.asked == []
        assert len(s.lost) == 1, "recovery being impossible must not mean " \
            "the call hangs on forever"

    def test_recovery_in_flight_suspends_the_deadline(self):
        async def _drive():
            s = _Watched()
            s.idle_for(V.VOICE_RX_DEAD_S + 1.0)
            s._recovering = True          # a rebuild owns the deadline
            await _spin(s)
            return s

        s = _run(_drive())
        assert s.lost == [], "a rebuild in flight was cut short"

    def test_exhausted_attempts_lead_to_teardown(self):
        async def _drive():
            s = _Watched()
            s._recover_attempts = V.VOICE_RECOVER_ATTEMPTS
            s.idle_for(V.VOICE_RX_DEAD_S + 1.0)
            await _spin(s)
            return s

        s = _run(_drive())
        assert s.asked == []
        assert len(s.lost) == 1

    def test_only_one_recovery_request_per_attempt(self):
        async def _drive():
            s = _Watched()
            s.idle_for(V.VOICE_RX_DEAD_S + 1.0)
            await _spin(s, rounds=6)
            return s

        s = _run(_drive())
        assert len(s.asked) == 1, "recovery storm: %d requests" % len(s.asked)

    def test_recovered_media_resets_the_attempt_budget(self):
        async def _drive():
            s = _Watched()
            s.idle_for(V.VOICE_RX_WARN_S + 1.0)
            task = asyncio.ensure_future(s._rx_watchdog())
            await asyncio.sleep(V.VOICE_RX_CHECK_S * 3)
            # Media genuinely resumes: the clock moves AND a frame
            # authenticated. The clock alone is not recovery -- see
            # TestRecoveryIsConfirmedByMediaNotByTheClock.
            s._rx_last_frame = V.time.monotonic()
            s._rx_last_datagram = s._rx_last_frame
            s._rx_authenticated += 1
            s._recovering = False
            await asyncio.sleep(V.VOICE_RX_CHECK_S * 3)
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            return s

        s = _run(_drive())
        assert s._recover_attempts == 0
        assert s._rx_degraded is False

    def test_healthy_media_never_asks_for_recovery(self):
        async def _drive():
            s = _Watched()
            await _spin(s)
            return s

        s = _run(_drive())
        assert s.asked == [] and s.lost == []


# ---------------------------------------------------------------------------
# 7. the manager: dispatch, call binding, and lifecycle races
# ---------------------------------------------------------------------------

class _OTR:
    def has_encrypted_session(self, peer):
        return True

    def is_smp_verified(self, peer):
        return True

    def get_smp_status(self, peer):
        return {"verified": True, "state": "SUCCEEDED"}

    def get_session(self, peer):
        return self

    def handle_outgoing_message(self, peer, body):
        return body, True


class _Client:
    def __init__(self):
        self.otr = _OTR()
        self.sent = []

    def _local_fp(self, peer=None):
        return "AA" * 64

    def _remote_fp(self, peer):
        return "BB" * 64

    def send_otr_fragmented(self, peer, frame):
        self.sent.append(frame)


PEER = "alice@example.i2p"


def _manager(loop):
    return V.VoiceCallManager(_Client(), loop)


def _managed(loop, is_initiator=False, call_id=CALL_ID):
    mgr = _manager(loop)
    session = _endpoint_session(is_initiator, call_id=call_id)
    session.peer = PEER
    session._recover_task = None
    session._recovering = False
    session._recover_attempts = 0
    session._running = True
    mgr._calls[PEER] = session
    return mgr, session


class TestManagerDispatch:

    def _loop(self):
        loop = asyncio.new_event_loop()
        return loop

    def test_a_valid_announcement_is_adopted_through_the_handler(self):
        loop = self._loop()
        try:
            mgr, res = _managed(loop, is_initiator=False)
            ini = _endpoint_session(True)
            ini._our_dest = DEST_B
            epoch, seq, dest, tag = ini.build_endpoint_announcement()
            loop.run_until_complete(mgr._on_media_path(
                PEER, [CALL_ID.hex(), str(epoch), str(seq), dest, tag.hex()]))
            assert res._peer_dest == V.i2p_public_destination(DEST_B)
        finally:
            loop.close()

    def test_an_announcement_for_another_call_is_ignored(self):
        loop = self._loop()
        try:
            mgr, res = _managed(loop, is_initiator=False)
            ini = _endpoint_session(True)
            ini._our_dest = DEST_B
            epoch, seq, dest, tag = ini.build_endpoint_announcement()
            loop.run_until_complete(mgr._on_media_path(
                PEER, [OTHER_CALL_ID.hex(), str(epoch), str(seq), dest,
                       tag.hex()]))
            assert res._peer_dest == DEST_A
        finally:
            loop.close()

    def test_two_calls_cannot_contaminate_each_others_endpoints(self):
        loop = self._loop()
        try:
            mgr, res = _managed(loop, is_initiator=False, call_id=CALL_ID)
            other = _endpoint_session(False, call_id=OTHER_CALL_ID)
            other.peer = "carol@example.i2p"
            mgr._calls["carol@example.i2p"] = other
            ini = _endpoint_session(True, call_id=CALL_ID)
            ini._our_dest = DEST_B
            epoch, seq, dest, tag = ini.build_endpoint_announcement()
            # Aimed at carol, carrying alice's call_id and alice's tag.
            loop.run_until_complete(mgr._on_media_path(
                "carol@example.i2p",
                [CALL_ID.hex(), str(epoch), str(seq), dest, tag.hex()]))
            assert other._peer_dest == DEST_A
        finally:
            loop.close()

    @pytest.mark.parametrize("fields", [
        [],
        [CALL_ID.hex()],
        [CALL_ID.hex(), "0", "1", DEST_B],
        [CALL_ID.hex(), "0", "1", DEST_B, "aa", "extra"],
    ])
    def test_a_malformed_announcement_is_a_signal_error(self, fields):
        loop = self._loop()
        try:
            mgr, _res = _managed(loop)
            with pytest.raises(V.SignalError):
                loop.run_until_complete(mgr._on_media_path(PEER, fields))
        finally:
            loop.close()

    @pytest.mark.parametrize("bad", ["", "zz", "-1", "notanumber"])
    def test_nonsense_numeric_fields_are_rejected(self, bad):
        loop = self._loop()
        try:
            mgr, res = _managed(loop)
            with pytest.raises(V.SignalError):
                loop.run_until_complete(mgr._on_media_path(
                    PEER, [CALL_ID.hex(), bad, "1", DEST_B,
                           "00" * V.CONFIRM_LEN]))
            assert res._peer_dest == DEST_A
        finally:
            loop.close()

    def test_an_empty_destination_is_refused(self):
        loop = self._loop()
        try:
            mgr, res = _managed(loop)
            loop.run_until_complete(mgr._on_media_path(
                PEER, [CALL_ID.hex(), "0", "1", "", "00" * V.CONFIRM_LEN]))
            assert res._peer_dest == DEST_A
        finally:
            loop.close()

    def test_announcements_are_rate_limited(self):
        loop = self._loop()
        try:
            mgr, res = _managed(loop, is_initiator=False)
            ini = _endpoint_session(True)
            accepted = 0
            for index in range(V.VOICE_MAX_MEDIAPATH_PER_MIN + 6):
                ini._our_dest = _real_dest(bytes([index + 10]))
                epoch, seq, dest, tag = ini.build_endpoint_announcement()
                before = res._peer_dest
                loop.run_until_complete(mgr._on_media_path(
                    PEER, [CALL_ID.hex(), str(epoch), str(seq), dest,
                           tag.hex()]))
                if res._peer_dest != before:
                    accepted += 1
            assert accepted <= V.VOICE_MAX_MEDIAPATH_PER_MIN, (
                "a peer can force unbounded endpoint churn")
        finally:
            loop.close()


class TestRecoveryLifecycle:

    def test_a_stall_on_a_replaced_call_starts_nothing(self):
        loop = asyncio.new_event_loop()
        try:
            mgr, _session = _managed(loop)
            mgr._handle_media_stalled(PEER, OTHER_CALL_ID)
            assert mgr._calls[PEER]._recover_task is None
        finally:
            loop.close()

    def test_a_stall_on_an_unknown_peer_starts_nothing(self):
        loop = asyncio.new_event_loop()
        try:
            mgr, _session = _managed(loop)
            mgr._handle_media_stalled("nobody@example.i2p", CALL_ID)
            assert mgr._calls[PEER]._recover_task is None
        finally:
            loop.close()

    def test_only_one_recovery_task_at_a_time(self):
        async def _drive():
            mgr, session = _managed(asyncio.get_event_loop())
            slow = asyncio.Event()

            async def _rebuild():
                await slow.wait()
                return DEST_B

            session.rebuild_media_endpoint = _rebuild
            mgr._handle_media_stalled(PEER, CALL_ID)
            first = session._recover_task
            mgr._handle_media_stalled(PEER, CALL_ID)
            assert session._recover_task is first, "duplicate recovery task"
            slow.set()
            first.cancel()
            try:
                await first
            except asyncio.CancelledError:
                pass

        asyncio.run(asyncio.wait_for(_drive(), 5))

    def test_a_rebuild_that_fails_hands_the_deadline_back(self):
        # Otherwise the watchdog would stay suspended and the call would
        # never be torn down.
        async def _drive():
            mgr, session = _managed(asyncio.get_event_loop())
            session._recovering = True

            async def _rebuild():
                raise RuntimeError("SAM refused")

            session.rebuild_media_endpoint = _rebuild
            await mgr._recover_media(PEER, CALL_ID)
            return session

        session = asyncio.run(asyncio.wait_for(_drive(), 5))
        assert session._recovering is False

    def test_a_rebuild_that_times_out_hands_the_deadline_back(self):
        async def _drive():
            mgr, session = _managed(asyncio.get_event_loop())
            session._recovering = True

            async def _rebuild():
                await asyncio.sleep(3600)

            session.rebuild_media_endpoint = _rebuild
            V.VOICE_RECOVER_TIMEOUT_S_SAVED = V.VOICE_RECOVER_TIMEOUT_S
            V.VOICE_RECOVER_TIMEOUT_S = 0.01
            try:
                await mgr._recover_media(PEER, CALL_ID)
            finally:
                V.VOICE_RECOVER_TIMEOUT_S = V.VOICE_RECOVER_TIMEOUT_S_SAVED
            return session

        session = asyncio.run(asyncio.wait_for(_drive(), 5))
        assert session._recovering is False

    def test_a_successful_rebuild_announces_the_new_endpoint(self):
        async def _drive():
            mgr, session = _managed(asyncio.get_event_loop(),
                                    is_initiator=True)
            session._recovering = True

            async def _rebuild():
                session._our_dest = DEST_C
                return DEST_C

            session.rebuild_media_endpoint = _rebuild
            await mgr._recover_media(PEER, CALL_ID)
            return mgr, session

        mgr, session = asyncio.run(asyncio.wait_for(_drive(), 5))
        announced = [f for f in mgr.client.sent if "MEDIAPATH" in f]
        assert len(announced) == 1
        assert session._recovering is False
        verb, fields = V.parse_signal(announced[0])
        assert verb == "MEDIAPATH"
        assert fields[0] == CALL_ID.hex()

    def test_a_call_that_ends_mid_rebuild_announces_nothing(self):
        async def _drive():
            mgr, session = _managed(asyncio.get_event_loop())

            async def _rebuild():
                mgr._calls.pop(PEER, None)      # torn down while we worked
                return DEST_C

            session.rebuild_media_endpoint = _rebuild
            await mgr._recover_media(PEER, CALL_ID)
            return mgr

        mgr = asyncio.run(asyncio.wait_for(_drive(), 5))
        assert [f for f in mgr.client.sent if "MEDIAPATH" in f] == []

    def test_a_call_replaced_mid_rebuild_is_not_announced_to(self):
        async def _drive():
            mgr, session = _managed(asyncio.get_event_loop())

            async def _rebuild():
                replacement = _endpoint_session(False,
                                                call_id=OTHER_CALL_ID)
                replacement.peer = PEER
                mgr._calls[PEER] = replacement
                return DEST_C

            session.rebuild_media_endpoint = _rebuild
            await mgr._recover_media(PEER, CALL_ID)
            return mgr

        mgr = asyncio.run(asyncio.wait_for(_drive(), 5))
        assert [f for f in mgr.client.sent if "MEDIAPATH" in f] == []

    def test_the_recovery_task_is_cancelled_by_teardown(self):
        import inspect
        src = inspect.getsource(V.VoiceCallSession.end)
        assert "_recover_task" in src

    def test_cancellation_also_hands_the_deadline_back(self):
        # Teardown cancels the task. If the flag survived, a session that
        # somehow outlived it would have a permanently suspended watchdog.
        async def _drive():
            mgr, session = _managed(asyncio.get_event_loop())
            session._recovering = True

            async def _rebuild():
                await asyncio.sleep(3600)

            session.rebuild_media_endpoint = _rebuild
            task = asyncio.ensure_future(mgr._recover_media(PEER, CALL_ID))
            await asyncio.sleep(0)
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            return session

        session = asyncio.run(asyncio.wait_for(_drive(), 5))
        assert session._recovering is False

    def test_recovery_is_cancellable(self):
        async def _drive():
            mgr, session = _managed(asyncio.get_event_loop())

            async def _rebuild():
                await asyncio.sleep(3600)

            session.rebuild_media_endpoint = _rebuild
            task = asyncio.ensure_future(mgr._recover_media(PEER, CALL_ID))
            await asyncio.sleep(0)
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                return True
            return False

        assert asyncio.run(asyncio.wait_for(_drive(), 5)) is True


class TestEndpointTeardown:

    def test_closing_the_datagram_transport_is_idempotent(self):
        s = object.__new__(V.VoiceCallSession)
        s._dgram_transport = None
        s._dgram_sock = None
        s._dgram_send_header = b"x"
        s._sam_control = None
        s._sam_session_id = "sess"
        s._sam_pending = []
        s._close_datagram_transport()
        s._close_datagram_transport()
        assert s._sam_session_id is None
        assert s._dgram_send_header is None

    def test_it_releases_the_sam_control_socket(self):
        released = []
        s = object.__new__(V.VoiceCallSession)
        s._dgram_transport = None
        s._dgram_sock = None
        s._dgram_send_header = None
        s._sam_control = object()
        s._sam_session_id = "sess"
        s._sam_pending = []
        saved = V._HOST.get("sam_release")
        V._HOST["sam_release"] = released.append
        try:
            s._close_datagram_transport()
        finally:
            V._HOST["sam_release"] = saved
        assert len(released) == 1, "the SAM session was leaked"
        assert s._sam_control is None

    def test_the_stream_transport_refuses_an_endpoint_rebuild(self):
        s = object.__new__(V.VoiceCallSession)
        s._transport_mode = V.VOICE_TRANSPORT_STREAM
        with pytest.raises(RuntimeError):
            asyncio.run(s.rebuild_media_endpoint())


# ---------------------------------------------------------------------------
# 8. two peers, real sockets: media stops, moves, and resumes
# ---------------------------------------------------------------------------

import os
import socket


def _media_session(is_initiator, call_id=CALL_ID):
    """A session with the real crypto, parser, jitter buffer and transport."""
    s = object.__new__(V.VoiceCallSession)
    s.call_id = call_id
    s.is_initiator = is_initiator
    s.state = V.CallState.ACTIVE
    s._running = True
    s._closing = False
    s.stats = V.new_media_stats()
    s._key_lock = threading.RLock()
    s._call_t0 = V.time.monotonic()
    s.stages = V.StageTimers()
    s.latency = V.LatencyTracker()
    s.jitter = V.JitterBuffer()
    s.schedule = V.VoiceKeySchedule(call_id, is_initiator)
    s.schedule.install_initial(ROOT)
    s._peer_cipher = V.VoiceFrameCrypto(bytearray(ROOT), call_id, 0,
                                        not is_initiator)
    s._foreign_warned = True
    s._rx_last_datagram = None
    s._rx_last_frame = None
    s._rx_degraded = False
    s._endpoint_seq_sent = 0
    s._endpoint_seq_seen = 0
    s._writer = None
    s._transport_mode = V.VOICE_TRANSPORT_DATAGRAM
    s._dgram_sock = None
    s._dgram_transport = None
    s._dgram_send_addr = None
    s._dgram_send_header = None
    s._sam_session_id = "sess-%s" % ("i" if is_initiator else "r")
    s._sam_control = None
    s._sam_pending = []
    s._rx_authenticated = 0
    s._rx_mark = 0
    s._peer_dest = None
    s._our_dest = None
    s.sam_host = "127.0.0.1"
    return s


def _sealed_audio(session, opus=b"\x01\x02\x03"):
    """A frame the PEER would send, sealed so `session` can open it."""
    return session._peer_cipher.seal(V.pad_opus(opus, send_ts_ms=1))


class _SamBridge(asyncio.DatagramProtocol):
    """What i2pd's SAM UDP bridge does: strip the header, tag the sender."""

    def __init__(self, sock, ports, dest_of):
        self.sock, self.ports, self.dest_of = sock, ports, dest_of
        self.dropped = 0
        self.blackhole = set()

    def datagram_received(self, data, addr):
        head, _, payload = data.partition(b"\n")
        try:
            _ver, _sid, dest = head.decode().split(" ", 2)
        except ValueError:
            return
        sender = self.dest_of.get(addr[1])
        target = self.ports.get(dest)
        if target is None or dest in self.blackhole:
            # The router no longer forwards to that destination: exactly what
            # a replaced session looks like from the outside.
            self.dropped += 1
            return
        self.sock.sendto(sender.encode() + b"\n" + payload,
                         ("127.0.0.1", target))


async def _body_media_moves_and_resumes():
    loop = asyncio.get_running_loop()
    ini, res = _media_session(True), _media_session(False)
    for s in (ini, res):
        s.loop = loop

    dest_ini, dest_res, dest_res_new = DEST_A, DEST_B, DEST_C
    port_ini = ini._bind_datagram_socket()
    port_res = res._bind_datagram_socket()
    ini._our_dest, res._our_dest = dest_ini, dest_res

    ports = {dest_ini: port_ini, dest_res: port_res}
    dest_of = {port_ini: dest_ini, port_res: dest_res}

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    sock.setblocking(False)
    bridge_port = sock.getsockname()[1]
    bridge = _SamBridge(sock, ports, dest_of)
    bridge_transport, _ = await loop.create_datagram_endpoint(
        lambda: bridge, sock=sock)

    saved = os.environ.get("OTRV4PLUS_SAM_UDP_PORT")
    os.environ["OTRV4PLUS_SAM_UDP_PORT"] = str(bridge_port)
    try:
        # The responder knows the caller's destination from the INVITE.
        res._peer_dest = dest_ini
        await ini.open_datagram_endpoint()
        await res.open_datagram_endpoint()

        # 1. Healthy media, both ways. The caller latches the callee's
        #    destination from the first frame that authenticates.
        res._write_packet(_sealed_audio(ini), None)
        await asyncio.sleep(0.1)
        assert ini.stats["recv"] == 1, "callee -> caller never flowed"
        assert ini._peer_dest == dest_res, "the caller never latched the peer"
        ini._write_packet(_sealed_audio(res), None)
        await asyncio.sleep(0.1)
        assert res.stats["recv"] == 1, "caller -> callee never flowed"
        healthy_at = res._rx_last_frame

        # 2. The network moves under the RESPONDER: the router stops
        #    forwarding to its destination, so its inbound dies while its
        #    outbound keeps being accepted -- the live failure exactly.
        bridge.blackhole.add(dest_res)
        ini._write_packet(_sealed_audio(res), None)
        await asyncio.sleep(0.1)
        assert res.stats["recv"] == 1, "the blackhole did not take effect"
        assert res._rx_last_frame == healthy_at
        assert ini.stats["sent"] == 2, "the sender noticed something, and " \
            "in the real failure it could not"

        # 3. It rebuilds onto a new session, port and destination.
        res._close_datagram_transport()
        res._sam_session_id = "sess-r2"
        port_res_new = res._bind_datagram_socket()
        res._our_dest = dest_res_new
        ports[dest_res_new] = port_res_new
        dest_of[port_res_new] = dest_res_new
        await res.open_datagram_endpoint()

        # 4. Announce over the authenticated hierarchy; the caller adopts.
        epoch, seq, dest, tag = res.build_endpoint_announcement()
        assert ini.accept_endpoint(epoch, seq, dest, tag) == "ok"
        assert ini._peer_dest == V.i2p_public_destination(dest_res_new)

        # 5. Media resumes on the new path, with the same keys and epoch.
        ini._write_packet(_sealed_audio(res), None)
        await asyncio.sleep(0.1)
        assert res.stats["recv"] == 2, "media did not resume after recovery"
        assert res._rx_last_frame > healthy_at
        assert res.stats["auth_fail"] == 0
        assert res.stats["replay"] == 0
        assert res.schedule.epoch == 0, "recovery disturbed the epoch"
        assert ini.schedule.epoch == 0

        # 6. And the reverse direction still works from the new session.
        before = ini.stats["recv"]
        res._write_packet(_sealed_audio(ini), None)
        await asyncio.sleep(0.1)
        assert ini.stats["recv"] == before + 1, "reverse path broke"
    finally:
        if saved is None:
            os.environ.pop("OTRV4PLUS_SAM_UDP_PORT", None)
        else:
            os.environ["OTRV4PLUS_SAM_UDP_PORT"] = saved
        bridge_transport.close()
        for s in (ini, res):
            s._close_datagram_transport()


def test_media_moves_and_resumes():
    asyncio.run(asyncio.wait_for(_body_media_moves_and_resumes(), 20))


async def _body_a_forged_move_does_not_redirect_media():
    """The same scenario, with an attacker's announcement instead."""
    loop = asyncio.get_running_loop()
    ini, res = _media_session(True), _media_session(False)
    for s in (ini, res):
        s.loop = loop
    port_ini = ini._bind_datagram_socket()
    port_res = res._bind_datagram_socket()
    ini._our_dest, res._our_dest = DEST_A, DEST_B
    ports = {DEST_A: port_ini, DEST_B: port_res}
    dest_of = {port_ini: DEST_A, port_res: DEST_B}
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    sock.setblocking(False)
    bridge = _SamBridge(sock, ports, dest_of)
    transport, _ = await loop.create_datagram_endpoint(lambda: bridge,
                                                       sock=sock)
    saved = os.environ.get("OTRV4PLUS_SAM_UDP_PORT")
    os.environ["OTRV4PLUS_SAM_UDP_PORT"] = str(sock.getsockname()[1])
    try:
        res._peer_dest = DEST_A
        await ini.open_datagram_endpoint()
        await res.open_datagram_endpoint()
        res._write_packet(_sealed_audio(ini), None)
        await asyncio.sleep(0.1)
        assert ini._peer_dest == DEST_B

        # An attacker who can write to the signalling channel but does not
        # hold the media root.
        assert ini.accept_endpoint(0, 1, DEST_C, b"\x00" * V.CONFIRM_LEN) == \
            "authentication failed"
        assert ini._peer_dest == DEST_B, "a forged move redirected media"

        before = ini.stats["recv"]
        res._write_packet(_sealed_audio(ini), None)
        await asyncio.sleep(0.1)
        assert ini.stats["recv"] == before + 1, "media stopped after a forgery"
    finally:
        if saved is None:
            os.environ.pop("OTRV4PLUS_SAM_UDP_PORT", None)
        else:
            os.environ["OTRV4PLUS_SAM_UDP_PORT"] = saved
        transport.close()
        for s in (ini, res):
            s._close_datagram_transport()


def test_a_forged_move_does_not_redirect_media():
    asyncio.run(asyncio.wait_for(_body_a_forged_move_does_not_redirect_media(),
                                 20))


# ---------------------------------------------------------------------------
# 9. what recovery must NOT disturb
# ---------------------------------------------------------------------------

class TestCryptographicStateSurvives:
    """Endpoint-only renegotiation, and why it needs no rekey.

    No media key derives from the destination: build_transcript covers the
    call_id, the OTR binding, both fingerprints, the X448 and ML-KEM material
    and the epoch, and nothing else. Moving the address therefore invalidates
    no key, which is exactly why this is an announcement rather than a rekey
    -- and why it must not be allowed to touch the epoch or the replay state.
    """

    def test_the_destination_is_not_part_of_the_transcript(self):
        # Checked on the signature, not the prose: the docstring discusses
        # destinations at length and a substring search matches that.
        import ast
        import inspect
        tree = ast.parse(inspect.getsource(V.build_transcript))
        fn = tree.body[0]
        params = [a.arg for a in fn.args.args]
        for name in params:
            assert "dest" not in name and "endpoint" not in name, (
                "the media keys depend on the endpoint (%s), so moving it "
                "would need a rekey rather than an announcement" % name)
        assert "call_id" in params and "epoch" in params

    def test_the_transcript_is_what_actually_derives_the_root(self):
        # Guards the test above from becoming vacuous if the derivation moves.
        import inspect
        assert "transcript" in inspect.getsource(V.derive_voice_root)

    def test_replay_protection_survives_an_endpoint_change(self):
        # A packet already accepted must stay rejected afterwards: recovery
        # moves an address, not a replay window.
        s = _media_session(False)
        packet = _sealed_audio(s)
        header, sealed = packet[:V.VOICE_HDR_LEN], packet[V.VOICE_HDR_LEN:]
        assert s.open_packet(header, sealed)[0] == 0
        ini = _endpoint_session(True)
        ini._our_dest = DEST_C
        s.state = V.CallState.ACTIVE
        s._peer_dest = DEST_A
        epoch, seq, dest, tag = ini.build_endpoint_announcement()
        assert s.accept_endpoint(epoch, seq, dest, tag) == "ok"
        with pytest.raises(V.FrameError) as exc:
            s.open_packet(header, sealed)
        assert "replay" in str(exc.value)

    def test_the_epoch_counter_is_untouched(self):
        ini, res = _endpoint_session(True, epoch=2), _endpoint_session(
            False, epoch=2)
        ini._our_dest = DEST_C
        before = res.schedule.epoch
        res.accept_endpoint(*ini.build_endpoint_announcement())
        assert res.schedule.epoch == before

    def test_a_pending_rekey_is_not_disturbed(self):
        ini, res = _endpoint_session(True), _endpoint_session(False)
        res.schedule.begin_rekey(1, bytes(V.ROOT_LEN))
        pending = res.schedule.pending_epoch
        ini._our_dest = DEST_C
        assert res.accept_endpoint(*ini.build_endpoint_announcement()) == "ok"
        assert res.schedule.pending_epoch == pending
        assert res.schedule.epoch == 0

    def test_an_announcement_during_a_pending_rekey_still_authenticates(self):
        # The committed epoch is what the tag is bound to, and a pending
        # rekey has not moved it.
        ini, res = _endpoint_session(True), _endpoint_session(False)
        ini.schedule.begin_rekey(1, bytes(V.ROOT_LEN))
        ini._our_dest = DEST_C
        assert res.accept_endpoint(*ini.build_endpoint_announcement()) == "ok"


class TestNoStorms:

    def test_an_xmpp_reconnect_does_not_touch_the_media_session(self):
        # Media and signalling hold independent SAM sessions. The reconnect
        # path must not rebuild a healthy media endpoint as a side effect.
        import inspect
        import otrv4plus_xmpp as X
        src = inspect.getsource(X.OTRv4PlusXMPP._reconnect)
        for name in ("rebuild_media_endpoint", "_close_datagram_transport",
                     "_handle_media_stalled", "MEDIAPATH"):
            assert name not in src

    def test_the_watchdog_is_the_only_thing_that_starts_recovery(self):
        import inspect
        src = inspect.getsource(V)
        callers = [line.strip() for line in src.split("\n")
                   if "_request_recovery()" in line
                   and "def " not in line]
        assert len(callers) == 1, "recovery has more than one trigger: %r" % (
            callers,)

    def test_a_rebuild_is_not_started_while_one_is_running(self):
        s = _Stalled()
        assert s._request_recovery() is True
        # _recovering stays set until the manager clears it, and the watchdog
        # skips the whole branch while it is set.
        assert s._recovering is True

    def test_recovery_state_does_not_leak_into_a_new_call(self):
        first = _endpoint_session(False, call_id=CALL_ID)
        first._endpoint_seq_seen = 12
        second = _endpoint_session(False, call_id=OTHER_CALL_ID)
        assert second._endpoint_seq_seen == 0
        assert second._endpoint_seq_sent == 0


# ---------------------------------------------------------------------------
# 10. what the adversarial pass on ee5dfc8 found
# ---------------------------------------------------------------------------

class TestRecoveryIsConfirmedByMediaNotByTheClock:
    """A rebuild resets the liveness clock, and that is not recovery.

    `rebuild_media_endpoint` re-stamps `_rx_last_frame` so the new path is not
    judged dead the instant it opens. The watchdog then read that small idle
    as success: it announced "inbound audio recovered" over a path that had
    delivered nothing, and handed the attempt budget back. Handing the budget
    back is the serious half -- it makes the rebuild loop unbounded, so a call
    can sit rebuilding forever instead of failing safe.

    Recovery is therefore confirmed by a frame that authenticated AFTER the
    rebuild, which is what `_rx_authenticated > _rx_mark` means.
    """

    def _degraded(self):
        s = _Watched()
        s.idle_for(V.VOICE_RX_DEAD_S + 1.0)
        s._rx_degraded = True
        s._recover_attempts = 1
        s._rx_authenticated = 7
        s._rx_mark = 7                      # nothing since the rebuild
        return s

    def _rebuilt(self, session, frames=0):
        """Do what a completed rebuild does to the session."""
        now = V.time.monotonic()
        session._rx_last_datagram = now
        session._rx_last_frame = now
        session._rx_mark = session._rx_authenticated
        session._recovering = False
        session._rx_authenticated += frames

    def test_a_rebuild_with_no_media_is_not_recovery(self):
        async def _drive():
            s = self._degraded()
            self._rebuilt(s, frames=0)
            await _spin(s, rounds=3)
            return s

        s = _run(_drive())
        assert s._rx_degraded is True, "silence was reported as recovery"
        assert s._recover_attempts == 1, "the attempt budget was handed back"

    def test_a_rebuild_that_delivers_media_is_recovery(self):
        async def _drive():
            s = self._degraded()
            self._rebuilt(s, frames=3)
            await _spin(s, rounds=3)
            return s

        s = _run(_drive())
        assert s._rx_degraded is False
        assert s._recover_attempts == 0

    def test_the_attempt_budget_still_runs_out_across_rebuilds(self):
        # The whole point: without this the loop never terminates.
        async def _drive():
            s = _Watched()
            s.idle_for(V.VOICE_RX_DEAD_S + 1.0)
            task = asyncio.ensure_future(s._rx_watchdog())
            for _ in range(V.VOICE_RECOVER_ATTEMPTS + 2):
                await asyncio.sleep(V.VOICE_RX_CHECK_S * 2)
                self._rebuilt(s, frames=0)      # every rebuild fails to help
                s.idle_for(V.VOICE_RX_DEAD_S + 1.0)
                if task.done():
                    break
            await asyncio.sleep(V.VOICE_RX_CHECK_S * 3)
            if not task.done():
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
            return s

        s = _run(_drive(), timeout=10)
        assert len(s.asked) <= V.VOICE_RECOVER_ATTEMPTS, (
            "unbounded rebuild loop: %d attempts" % len(s.asked))
        assert s.lost, "the call never failed safe"

    def test_only_an_authenticated_frame_moves_the_counter(self):
        s = _media_session(False)
        before = s._rx_authenticated
        s._on_datagram(b"junk that never authenticates")
        assert s._rx_authenticated == before
        s._peer_dest = None
        s._on_datagram(_sealed_audio(s))
        assert s._rx_authenticated == before + 1

    def test_a_probe_reply_counts_as_recovery_evidence(self):
        # PONGs are inbound media too, and during the live failure they died
        # with the audio. A path delivering probes is not dead.
        s = _media_session(False)
        s.latency.handle_pong = lambda payload: None
        before = s._rx_authenticated
        packet = s._peer_cipher.seal(V.pad_opus(b"\x01", send_ts_ms=1),
                                     frame_type=V.FRAME_TYPE_PONG)
        s._on_datagram(packet)
        assert s._rx_authenticated == before + 1

    def test_start_audio_primes_the_mark(self):
        import inspect
        src = inspect.getsource(V.VoiceCallSession.start_audio)
        assert "_rx_mark = self._rx_authenticated" in src

    def test_the_rebuild_sets_the_mark(self):
        import inspect
        src = inspect.getsource(V.VoiceCallSession.rebuild_media_endpoint)
        assert "_rx_mark = self._rx_authenticated" in src


class TestNoSamSessionLeakOnACancelledRebuild:
    """SESSION CREATE runs in an executor; cancelling the await does not stop it.

    `asyncio.wait_for` cancels the coroutine, the thread keeps running, and
    when it finishes it returns a live control socket to a caller that has
    gone. Nothing then holds a reference, so the socket -- and the router-side
    SAM session behind it -- stays open for the life of the process. Recovery
    is the first place in this codebase where create_session is genuinely
    cancelled, so the exposure arrived with it.
    """

    def _host(self, opened, delay=0.4):
        import socket as _s

        def _open(host, port, timeout):
            a, b = _s.socketpair()
            opened.append((a, b))
            return a

        def _read(sock, timeout):
            V.time.sleep(delay)
            body = (b"\x01" * 384) + bytes([5]) + (4).to_bytes(2, "big") \
                + b"cert"
            return ("SESSION STATUS RESULT=OK DESTINATION=%s"
                    % V.i2p_b64encode(body))

        def _parse(line, prefix):
            return dict(p.split("=", 1) for p in line[len(prefix):].split())

        return _open, _read, _parse

    def _session(self, loop):
        s = object.__new__(V.VoiceCallSession)
        s.loop = loop
        s.sam_host, s.sam_port = "127.0.0.1", 7656
        s._transport_mode = V.VOICE_TRANSPORT_DATAGRAM
        s._dgram_sock = None
        s._dgram_transport = None
        s._dgram_send_header = None
        s._sam_control = None
        s._sam_session_id = None
        s._our_dest = None
        s._sam_pending = []
        return s

    def test_a_cancelled_create_leaves_the_socket_reclaimable(self):
        opened = []
        saved = {k: V._HOST[k] for k in ("sam_open", "sam_read_line",
                                         "sam_parse")}

        async def _drive():
            s = self._session(asyncio.get_event_loop())
            with pytest.raises(asyncio.TimeoutError):
                await asyncio.wait_for(s.create_session(), timeout=0.05)
            await asyncio.sleep(0.8)        # let the executor thread finish
            assert s._sam_pending, (
                "the in-flight socket was not published to the session")
            s._close_datagram_transport()
            return s

        _open, _read, _parse = self._host(opened)
        V.bind_host(sam_open=_open, sam_read_line=_read, sam_parse=_parse)
        try:
            asyncio.run(asyncio.wait_for(_drive(), 10))
        finally:
            V._HOST.update(saved)
            live = [a for a, _b in opened if a.fileno() != -1]
            for a, b in opened:
                for sock in (a, b):
                    try:
                        sock.close()
                    except Exception:
                        pass
        assert live == [], "a SAM control socket outlived the call"

    def test_a_successful_create_leaves_nothing_pending(self):
        opened = []
        saved = {k: V._HOST[k] for k in ("sam_open", "sam_read_line",
                                         "sam_parse")}

        async def _drive():
            s = self._session(asyncio.get_event_loop())
            await s.create_session()
            assert s._sam_control is not None
            assert s._sam_pending == [], "the live session is still 'pending'"
            s._close_datagram_transport()
            return s

        _open, _read, _parse = self._host(opened, delay=0.0)
        V.bind_host(sam_open=_open, sam_read_line=_read, sam_parse=_parse)
        try:
            asyncio.run(asyncio.wait_for(_drive(), 10))
        finally:
            V._HOST.update(saved)
            for a, b in opened:
                for sock in (a, b):
                    try:
                        sock.close()
                    except Exception:
                        pass

    def test_the_recovery_budget_bounds_the_blocking_read(self):
        # Otherwise the executor thread outlives the deadline its caller is
        # held to -- SAM_SESSION_TIMEOUT is 300 s against a 150 s budget.
        import inspect
        src = inspect.getsource(V.VoiceCallSession.rebuild_media_endpoint)
        assert "session_timeout=VOICE_RECOVER_TIMEOUT_S" in src
        create = inspect.getsource(V.VoiceCallSession.create_session)
        assert "sam_read_line(ctrl, session_timeout)" in create

    def test_draining_pending_sockets_is_idempotent(self):
        s = object.__new__(V.VoiceCallSession)
        s._dgram_transport = None
        s._dgram_sock = None
        s._dgram_send_header = None
        s._sam_control = None
        s._sam_session_id = None
        s._sam_pending = []
        s._close_datagram_transport()
        s._close_datagram_transport()
        assert s._sam_pending == []


class TestTheWorstCaseIsBounded:
    """The time from media death to teardown, computed from the constants.

    Each rebuild resets the liveness clock so the new path is not judged dead
    the instant it opens. Teardown therefore needs DEAD seconds of silence
    measured from the LAST reset, not from the original failure -- which makes
    the bound one detect-interval per attempt longer than a naive
    WARN + attempts x REBUILD sum suggests.
    """

    @staticmethod
    def worst_case_seconds():
        total = V.VOICE_RX_WARN_S
        for attempt in range(1, V.VOICE_RECOVER_ATTEMPTS + 1):
            total += V.VOICE_RECOVER_TIMEOUT_S
            total += (V.VOICE_RX_WARN_S
                      if attempt < V.VOICE_RECOVER_ATTEMPTS
                      else V.VOICE_RX_DEAD_S)
        return total

    def test_the_bound_is_finite(self):
        assert self.worst_case_seconds() < 10 * 60

    def test_the_documented_bound_matches_the_constants(self):
        # VOICE_MEDIA_PATH.md states this number; if a constant moves and the
        # document does not, this fails rather than the document quietly
        # becoming wrong.
        text = open("VOICE_MEDIA_PATH.md", encoding="utf-8").read()
        assert "%d s" % int(self.worst_case_seconds()) in text, (
            "the documented worst case does not match the constants "
            "(computed %d s)" % self.worst_case_seconds())

    def test_every_stage_of_the_bound_is_enforced_somewhere(self):
        import inspect
        watchdog = inspect.getsource(V.VoiceCallSession._rx_watchdog)
        recover = inspect.getsource(V.VoiceCallManager._recover_media)
        possible = inspect.getsource(V.VoiceCallSession._recovery_possible)
        assert "VOICE_RX_WARN_S" in watchdog
        assert "VOICE_RX_DEAD_S" in watchdog
        assert "timeout=VOICE_RECOVER_TIMEOUT_S" in recover
        assert "VOICE_RECOVER_ATTEMPTS" in possible

    def test_disabling_recovery_restores_the_plain_fail_safe(self):
        # OTRV4PLUS_RECOVER_ATTEMPTS=0 is the escape hatch for a user who
        # would rather the call drop than wait through a rebuild.
        s = _Stalled()
        saved = V.VOICE_RECOVER_ATTEMPTS
        V.VOICE_RECOVER_ATTEMPTS = 0
        try:
            assert s._recovery_possible() is False
        finally:
            V.VOICE_RECOVER_ATTEMPTS = saved
