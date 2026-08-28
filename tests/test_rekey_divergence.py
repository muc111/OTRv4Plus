#!/usr/bin/env python3
"""INV-16: a rekey never strands the two peers on unreachable key states.

The failure this exists for
---------------------------
A 69-minute live I2P call rekeyed successfully, then stopped: the last ~40
attempts all failed and authentication failures appeared.  Two defects in the
state machine can produce exactly that, and both are exercised here.

1.  `abort_rekey` removed the pending epoch's cipher from the RECEIVE set.
    The initiator commits an epoch the moment the responder's tag verifies
    and only then sends REKEYCOMMIT, so it is already SENDING on the new
    epoch while the responder still has it merely pending.  A responder that
    aborted -- on a timeout, or superseded by a later REKEY -- could no
    longer decrypt anything the peer sent.  Every frame landed in
    `auth_fail`: one-way audio that reads like a broken tunnel.

2.  `_on_rekey` required the incoming epoch to be exactly `ours + 1`.  A
    responder that missed a REKEYCOMMIT stayed an epoch behind forever,
    because every subsequent REKEY was for an epoch it considered two ahead
    and was rejected -- including the ones that would have repaired it.

These tests drive the real `VoiceKeySchedule`, not a model of it.
"""

import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

V = pytest.importorskip("otrv4plus_voice")

CALL = bytes(range(16))
ROOT0 = bytes(range(64))


def _pair():
    a = V.VoiceKeySchedule(CALL, True)     # initiator
    b = V.VoiceKeySchedule(CALL, False)    # responder
    a.install_initial(bytearray(ROOT0))
    b.install_initial(bytearray(ROOT0))
    return a, b


def _root(epoch):
    return bytearray(bytes([epoch % 256]) * 64)


def _round(a, b, epoch, deliver_ack=True, deliver_commit=True):
    """One rekey, with selectable control-message loss.

    Returns (initiator_tag, responder_tag) so a caller can deliver a message
    later than it would have arrived.
    """
    a.begin_rekey(epoch, _root(epoch))
    b.begin_rekey(epoch, _root(epoch))
    init_tag = a.our_confirm()             # travels in REKEYCOMMIT
    resp_tag = b.our_confirm()             # travels in REKEYACK
    if deliver_ack:
        a.commit_rekey(epoch, resp_tag)
        if deliver_commit:
            b.commit_rekey(epoch, init_tag)
    return init_tag, resp_tag


def _can_receive(sched, epoch):
    return sched.cipher_for_epoch(epoch) is not None


# --------------------------------------------------------------------------
# A: one peer committing while the other has not
# --------------------------------------------------------------------------

class TestOneSidedCommit:

    def test_a_lost_commit_leaves_the_peers_on_different_send_epochs(self):
        """Q(A).  This is allowed -- it is the window the design accepts."""
        a, b = _pair()
        _round(a, b, 1, deliver_commit=False)
        assert a.epoch == 1 and b.epoch == 0

    def test_but_both_directions_still_decrypt(self):
        """Which is what makes that window survivable."""
        a, b = _pair()
        _round(a, b, 1, deliver_commit=False)
        assert _can_receive(b, a.epoch), (
            "the initiator is sending on an epoch the responder cannot read")
        assert _can_receive(a, b.epoch), (
            "the responder is sending on an epoch the initiator cannot read")


# --------------------------------------------------------------------------
# B: discarding a key the peer is still sending under
# --------------------------------------------------------------------------

class TestAbortKeepsTheReceiveKey:

    def test_a_timeout_abort_keeps_the_receive_cipher(self):
        """Q(B).  The regression that caused the one-way audio."""
        a, b = _pair()
        _round(a, b, 1, deliver_commit=False)
        b.abort_rekey()                      # timeout / superseded
        assert _can_receive(b, 1), (
            "aborting on silence destroyed the key the peer is already "
            "sending under")

    def test_a_timeout_abort_still_stops_us_sending_on_it(self):
        a, b = _pair()
        _round(a, b, 1, deliver_commit=False)
        b.abort_rekey()
        assert b.epoch == 0
        assert b.pending_epoch is None

    def test_a_tag_mismatch_does_discard_the_receive_cipher(self):
        """Silence is not evidence; a bad tag is."""
        a, b = _pair()
        b.begin_rekey(1, _root(1))
        assert _can_receive(b, 1)
        b.abort_rekey(discard_receive=True)
        assert not _can_receive(b, 1), (
            "material whose confirmation failed is still able to decrypt")

    def test_commit_with_a_bad_tag_discards(self):
        a, b = _pair()
        b.begin_rekey(1, _root(1))
        assert b.commit_rekey(1, b"\x00" * V.CONFIRM_LEN) is False
        assert not _can_receive(b, 1)
        assert b.epoch == 0, "a forged tag moved the committed epoch"

    def test_the_default_is_the_safe_one(self):
        """A caller that does not think about it must not destroy a live key."""
        import inspect
        sig = inspect.signature(V.VoiceKeySchedule.abort_rekey)
        assert sig.parameters["discard_receive"].default is False


# --------------------------------------------------------------------------
# F: indefinite divergence
# --------------------------------------------------------------------------

class TestTheResponderCanCatchUp:

    def test_a_responder_behind_by_one_accepts_the_next_epoch(self):
        """Q(F).  Previously rejected forever."""
        a, b = _pair()
        _round(a, b, 1, deliver_commit=False)
        b.abort_rekey()
        assert a.epoch == 1 and b.epoch == 0
        # The initiator now asks for epoch 2.  The responder is on 0.
        b.begin_rekey(2, _root(2))
        assert b.pending_epoch == 2, "the responder cannot rejoin"

    def test_catching_up_still_requires_a_valid_tag_to_commit(self):
        a, b = _pair()
        b.begin_rekey(5, _root(5))
        assert b.commit_rekey(5, b"\xff" * V.CONFIRM_LEN) is False
        assert b.epoch == 0, "a forward jump committed without a valid tag"

    def test_a_full_catch_up_converges(self):
        a, b = _pair()
        _round(a, b, 1, deliver_commit=False)
        b.abort_rekey()
        init_tag, resp_tag = _round(a, b, 2, deliver_ack=False)
        a.commit_rekey(2, resp_tag)
        b.commit_rekey(2, init_tag)
        assert a.epoch == b.epoch == 2, "the peers did not reconverge"

    def test_the_epoch_never_moves_backwards(self):
        a, b = _pair()
        _round(a, b, 1)
        _round(a, b, 2)
        with pytest.raises(ValueError):
            b.begin_rekey(1, _root(1))
        with pytest.raises(ValueError):
            b.begin_rekey(2, _root(2))
        assert b.epoch == 2

    def test_an_implausible_jump_is_refused(self):
        """Catching up must not become "derive as far ahead as I say"."""
        a, b = _pair()
        with pytest.raises(ValueError):
            b.begin_rekey(V.VoiceKeySchedule.MAX_CATCHUP + 2, _root(3))

    def test_the_catchup_bound_is_bounded(self):
        assert 1 < V.VoiceKeySchedule.MAX_CATCHUP <= 1024
        assert V.VOICE_REKEY_MAX_CATCHUP == V.VoiceKeySchedule.MAX_CATCHUP, (
            "the signalling layer and the key schedule disagree about how "
            "far a catch-up may go, so one of them is unreachable")


# --------------------------------------------------------------------------
# H: old packets after a reconnect
# --------------------------------------------------------------------------

class TestRetiredEpochsStayRetired:

    def test_epochs_are_retired_after_the_retention_window(self):
        """Q(H).  A delayed packet from long ago must not decrypt."""
        a, b = _pair()
        for e in (1, 2, 3):
            _round(a, b, e)
        assert not _can_receive(a, 0)
        assert not _can_receive(a, 1)
        assert _can_receive(a, 2), "the retention window is too narrow"
        assert _can_receive(a, 3)

    def test_retention_is_exactly_one_epoch(self):
        assert V.VoiceKeySchedule.RETAIN_EPOCHS == 1

    def test_a_retained_receive_key_is_dropped_once_the_epoch_moves_on(self):
        """The abort change must not make keys immortal."""
        a, b = _pair()
        _round(a, b, 1, deliver_commit=False)
        b.abort_rekey()
        assert _can_receive(b, 1)
        for e in (2, 3, 4):
            b.begin_rekey(e, _root(e))
            b.commit_rekey(e, _peer_tag(b, e))
        assert not _can_receive(b, 1), (
            "a retained receive key survived four epochs")


def _peer_tag(sched, epoch):
    """The tag the peer would send for `sched`'s pending epoch."""
    ci, cr = sched._pending["confirms"]
    return cr if sched.is_initiator else ci


# --------------------------------------------------------------------------
# J: is there positive evidence both peers switched?
# --------------------------------------------------------------------------

class TestCommitEvidence:

    def test_the_initiator_has_no_proof_the_responder_committed(self):
        """Q(J).  Documented gap, not a fixed one.

        Closing it needs a fourth message and therefore a wire change.  What
        the fixes above provide instead is convergence: the peers always
        REACH agreement, even though neither can prove at the moment of
        commit that the other has.
        """
        a, b = _pair()
        _round(a, b, 1, deliver_commit=False)
        assert a.rekeys_committed == 1
        assert b.rekeys_committed == 0
        # The initiator's own counter reads success while the peer is behind.
        # If a future change adds an acknowledgement, this test should be
        # replaced by one asserting the acknowledgement exists.

    def test_convergence_is_what_replaces_proof(self):
        a, b = _pair()
        _round(a, b, 1, deliver_commit=False)
        b.abort_rekey()
        init_tag, resp_tag = _round(a, b, 2, deliver_ack=False)
        a.commit_rekey(2, resp_tag)
        b.commit_rekey(2, init_tag)
        assert a.epoch == b.epoch
