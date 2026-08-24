#!/usr/bin/env python3
"""Rekey liveness: one lost control message must not stop rekeying forever.

Two failures of the same family, both observed or reachable on a real call:

  A. The responder's REKEYACK is lost.  The initiator times out, aborts and
     retries the same epoch — but the responder still held that epoch as
     `pending`, and the pending guard rejected every retry.  A 69-minute
     call rekeyed 12 times, lost one exchange, then failed all 15 remaining
     attempts: no forward-secrecy refresh for the last 40 minutes.

  B. The initiator's REKEYCOMMIT is lost.  The initiator has already
     committed epoch N+1, so its next REKEY names N+2, which the responder
     rejects as a skipped epoch.  Permanent, in the other direction.

The fixes are symmetric with what already existed: the responder gets the
same expiry the initiator has, and the initiator repeats its last commit
with each new REKEY.  Neither changes the wire format, the key schedule, or
what a confirmation tag proves.
"""

import asyncio
import os
import unittest

os.environ.setdefault("OTRV4PLUS_ALLOW_PYTHON_MLKEM", "1")

import otrv4plus_voice as V


CALL_ID = bytes(range(16))
FP_A = "AA" * 64
FP_B = "BB" * 64
OTR_BINDING = b"OTRv4+Voice/session/v3"
ROOT = bytes(range(32)) * (V.ROOT_LEN // 32)


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
        return FP_A

    def _remote_fp(self, peer):
        return FP_B

    def send_otr_fragmented(self, peer, frame):
        self.sent.append(frame)


class _RekeyBase(unittest.TestCase):

    IS_INITIATOR = False

    def setUp(self):
        self.loop = asyncio.new_event_loop()
        self.addCleanup(self.loop.close)
        self.client = _Client()
        self.mgr = V.VoiceCallManager(self.client, self.loop)
        self.peer = "peer@example.org"
        self.session = V.VoiceCallSession(self.peer, self.loop, CALL_ID,
                                          self.IS_INITIATOR)
        self.session.otr_material = (OTR_BINDING, FP_A, FP_B)
        self.session.state = V.CallState.ACTIVE
        self.session.schedule.install_initial(ROOT)
        self.mgr._calls[self.peer] = self.session

    # -- helpers ----------------------------------------------------------

    def signals(self, verb=None):
        out = []
        for frame in self.client.sent:
            try:
                got, fields = V.parse_signal(frame)
            except V.SignalError:
                continue
            if verb is None or got == verb:
                out.append((got, fields))
        return out

    def rekey_offer(self, epoch):
        """A well-formed REKEY from a real initiator key exchange."""
        kex = V.VoiceKeyExchange(True)
        return kex, [CALL_ID.hex(), str(epoch), kex.public.hex(),
                     kex.mlkem_ek.hex()]

    def deliver(self, coro):
        self.loop.run_until_complete(coro)

    def age_pending(self, seconds):
        """Backdate the pending rekey so it looks `seconds` old."""
        pending = self.session.schedule._pending
        self.assertIsNotNone(pending, "no pending rekey to age")
        pending["started"] -= seconds


# ===========================================================================
# A. the responder's pending epoch expires
# ===========================================================================

class TestResponderPendingExpiry(_RekeyBase):

    IS_INITIATOR = False

    def _offer(self, epoch=1):
        kex, fields = self.rekey_offer(epoch)
        self.deliver(self.mgr._on_rekey(self.peer, fields))
        return kex

    def test_pending_age_tracks_the_derivation(self):
        self.assertIsNone(self.session.schedule.pending_age)
        self._offer()
        age = self.session.schedule.pending_age
        self.assertIsNotNone(age)
        self.assertLess(age, 1.0)

    def test_first_rekey_is_answered(self):
        self._offer()
        self.assertEqual(self.session.schedule.pending_epoch, 1)
        self.assertEqual(len(self.signals("REKEYACK")), 1)

    def test_fresh_pending_is_protected_from_a_duplicate(self):
        self._offer()
        before = self.session.schedule.our_confirm()
        self._offer()          # replay / duplicate, arriving immediately
        self.assertEqual(len(self.signals("REKEYACK")), 1,
                         "a duplicate REKEY restarted a live exchange")
        self.assertEqual(self.session.schedule.our_confirm(), before)

    def test_stale_pending_is_superseded(self):
        self._offer()
        before = self.session.schedule.our_confirm()
        self.age_pending(V.VOICE_REKEY_TIMEOUT + 1)
        self._offer()
        self.assertEqual(len(self.signals("REKEYACK")), 2,
                         "a stale pending epoch still blocked the retry")
        self.assertEqual(self.session.schedule.pending_epoch, 1)
        self.assertNotEqual(self.session.schedule.our_confirm(), before,
                            "the retry reused the abandoned key material")

    def test_supersede_never_moves_the_committed_epoch(self):
        self._offer()
        self.age_pending(V.VOICE_REKEY_TIMEOUT + 1)
        self._offer()
        self.assertEqual(self.session.schedule.epoch, 0)

    def test_supersede_retires_the_abandoned_receive_cipher(self):
        self._offer()
        abandoned = self.session.schedule.cipher_for_epoch(1)
        self.age_pending(V.VOICE_REKEY_TIMEOUT + 1)
        self._offer()
        self.assertIsNot(self.session.schedule.cipher_for_epoch(1), abandoned,
                         "the abandoned epoch could still decrypt")

    def test_repeated_retries_all_get_through(self):
        # The live failure was not one blocked retry but every one of them.
        for _ in range(5):
            self._offer()
            self.age_pending(V.VOICE_REKEY_TIMEOUT + 1)
        self.assertEqual(len(self.signals("REKEYACK")), 5)

    def test_epoch_guard_still_holds_after_a_supersede(self):
        self._offer()
        self.age_pending(V.VOICE_REKEY_TIMEOUT + 1)
        _, skipped = self.rekey_offer(3)         # two ahead — not ours
        self.deliver(self.mgr._on_rekey(self.peer, skipped))
        self.assertEqual(len(self.signals("REKEYACK")), 1)
        self.assertEqual(self.session.schedule.pending_epoch, 1,
                         "a skipped epoch disturbed the pending exchange")
        self.assertEqual(self.session.schedule.epoch, 0)


# ===========================================================================
# B. the initiator repeats its last commit
# ===========================================================================

class TestCommitRetransmission(_RekeyBase):

    IS_INITIATOR = True

    def _start_rekey(self):
        """Run _initiate_rekey up to the point where it waits for REKEYACK."""
        task = self.loop.create_task(
            self.mgr._initiate_rekey(self.peer, self.session))
        for _ in range(8):
            self.loop.run_until_complete(asyncio.sleep(0))
        task.cancel()
        try:
            self.loop.run_until_complete(task)
        except asyncio.CancelledError:
            pass
        return task

    def test_nothing_is_repeated_before_the_first_commit(self):
        self._start_rekey()
        self.assertEqual(self.signals("REKEYCOMMIT"), [])
        self.assertEqual(len(self.signals("REKEY")), 1)

    def test_the_last_commit_is_repeated_with_the_next_rekey(self):
        self.session._last_rekey_commit = (1, "ab" * V.CONFIRM_LEN)
        self._start_rekey()
        verbs = [verb for verb, _ in self.signals()]
        self.assertEqual(verbs, ["REKEYCOMMIT", "REKEY"],
                         "the commit must precede the request it repairs")
        _, fields = self.signals("REKEYCOMMIT")[0]
        self.assertEqual(fields[:2], [CALL_ID.hex(), "1"])
        self.assertEqual(fields[2], "ab" * V.CONFIRM_LEN)

    def test_the_repeat_names_the_call(self):
        self.session._last_rekey_commit = (1, "ab" * V.CONFIRM_LEN)
        self._start_rekey()
        _, fields = self.signals("REKEYCOMMIT")[0]
        self.assertEqual(fields[0], CALL_ID.hex())


class TestResponderAcceptsTheRepeat(_RekeyBase):

    IS_INITIATOR = False

    def _pending(self, epoch=1):
        _, fields = self.rekey_offer(epoch)
        self.deliver(self.mgr._on_rekey(self.peer, fields))
        return self.session.schedule.expected_peer_confirm()

    def test_a_repeated_commit_lands_the_epoch_that_was_lost(self):
        peer_confirm = self._pending()
        self.deliver(self.mgr._on_rekey_commit(
            self.peer, [CALL_ID.hex(), "1", peer_confirm.hex()]))
        self.assertEqual(self.session.schedule.epoch, 1)
        self.assertIsNone(self.session.schedule.pending_epoch)

    def test_a_second_copy_changes_nothing(self):
        peer_confirm = self._pending()
        fields = [CALL_ID.hex(), "1", peer_confirm.hex()]
        self.deliver(self.mgr._on_rekey_commit(self.peer, fields))
        committed = self.session.schedule.rekeys_committed
        self.deliver(self.mgr._on_rekey_commit(self.peer, fields))
        self.assertEqual(self.session.schedule.epoch, 1)
        self.assertEqual(self.session.schedule.rekeys_committed, committed)
        self.assertEqual(self.session.schedule.rekeys_failed, 0)

    def test_a_forged_repeat_cannot_promote_an_epoch(self):
        self._pending()
        self.deliver(self.mgr._on_rekey_commit(
            self.peer, [CALL_ID.hex(), "1", "00" * V.CONFIRM_LEN]))
        self.assertEqual(self.session.schedule.epoch, 0,
                         "a forged tag moved the committed epoch")

    def test_a_stale_repeat_cannot_rewind_the_epoch(self):
        peer_confirm = self._pending()
        self.deliver(self.mgr._on_rekey_commit(
            self.peer, [CALL_ID.hex(), "1", peer_confirm.hex()]))
        self.deliver(self.mgr._on_rekey_commit(
            self.peer, [CALL_ID.hex(), "0", "00" * V.CONFIRM_LEN]))
        self.assertEqual(self.session.schedule.epoch, 1)

    def test_the_repeat_is_ignored_by_the_initiator_side(self):
        # REKEYCOMMIT is responder-only; the initiator must never act on one.
        self.session.is_initiator = True
        self._pending_epoch_via_schedule()
        self.deliver(self.mgr._on_rekey_commit(
            self.peer, [CALL_ID.hex(), "1", "00" * V.CONFIRM_LEN]))
        self.assertEqual(self.session.schedule.epoch, 0)

    def _pending_epoch_via_schedule(self):
        self.session.schedule.begin_rekey(1, bytes(V.ROOT_LEN))


if __name__ == "__main__":
    unittest.main(verbosity=2)
