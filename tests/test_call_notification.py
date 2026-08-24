#!/usr/bin/env python3
"""Incoming-call UX: notification, ringtone, and ACCEPT/DECLINE buttons.

A Termux notification action is a shell command run by the Termux app in a
separate process, so the buttons cannot call into the client directly. They
write one line into a FIFO the client reads, and that line is turned back
into the same answer_call()/reject_call() the terminal calls.

That makes the button a new *input* to the call state machine, which is the
part worth testing hard:

  * nothing peer-derived may reach a shell command, and no peer text may be
    parsed by termux-notification as one of its own options;
  * a token is single-use and bound to one (peer, call_id), so a replayed or
    stale press cannot answer the call that replaced it;
  * a press is re-checked against live session state, so it can only act on
    a call that is actually ringing;
  * none of it is reachable at all unless the client already decided to ring
    — which is downstream of the SMP gate.
"""

import asyncio
import os
import stat
import tempfile
import unittest

os.environ.setdefault("OTRV4PLUS_ALLOW_PYTHON_MLKEM", "1")

import otrv4plus_audio as A
import otrv4plus_voice as V


CALL_ID = bytes(range(16))
OTHER_CALL_ID = bytes(range(16, 32))
PEER = "bob@example.org"
FIFO_PATH_OK = "/data/data/com.termux/files/home/.otrv4plus/call-ctl"


# ===========================================================================
# 1. the notification command line
# ===========================================================================

class TestNotificationArgv(unittest.TestCase):

    def argv(self, actions=(), content=PEER):
        r = A.Ringer(notify=False, vibrate=False, actions=list(actions))
        return r._notify_argv("/bin/termux-notification", content)

    def good_command(self, verb="answer"):
        return ("test -p '%s' && printf '%s ab12\\n' > '%s'"
                % (FIFO_PATH_OK, verb, FIFO_PATH_OK))

    def test_no_actions_keeps_the_original_notification(self):
        argv = self.argv()
        self.assertIn("--priority", argv)
        self.assertIn("--sound", argv)
        self.assertNotIn("--button1", argv)

    def test_actions_render_as_buttons(self):
        argv = self.argv([("Answer", self.good_command("answer")),
                          ("Decline", self.good_command("decline"))])
        self.assertEqual(argv[argv.index("--button1") + 1], "Answer")
        self.assertEqual(argv[argv.index("--button2") + 1], "Decline")
        self.assertIn(self.good_command("answer"), argv)
        self.assertIn(self.good_command("decline"), argv)

    def test_at_most_two_buttons_are_ever_built(self):
        r = A.Ringer(notify=False, vibrate=False,
                     actions=[("a", self.good_command())] * 5)
        self.assertLessEqual(len(r._actions), A.Ringer.MAX_BUTTONS)

    def test_a_command_we_did_not_generate_is_dropped(self):
        for hostile in ("printf x > /y; rm -rf $HOME",
                        "`id`",
                        "printf 'x\n' > /y",
                        "$(cat /etc/passwd)",
                        "x" * 900,
                        ""):
            argv = self.argv([("Answer", hostile)])
            self.assertNotIn("--button1", argv,
                             "accepted a hostile action: %r" % hostile)

    def test_a_dropped_button_does_not_drop_the_notification(self):
        argv = self.argv([("Answer", "`id`")])
        self.assertIn("--title", argv)
        self.assertIn("--sound", argv)

    def test_a_jid_cannot_become_an_option(self):
        argv = self.argv(content="-e@evil.org")
        self.assertNotIn("-e@evil.org", argv)
        self.assertIn(" -e@evil.org", argv)

    def test_control_characters_are_stripped_from_the_jid(self):
        cleaned = A.Ringer._clean("bob\x1b[31m\x00\nevil@example.org")
        self.assertNotIn("\x1b", cleaned)
        self.assertNotIn("\x00", cleaned)
        self.assertNotIn("\n", cleaned)

    def test_the_jid_is_length_capped(self):
        self.assertLessEqual(len(A.Ringer._clean("a" * 500)), 96)

    def test_privacy_mode_still_keeps_the_jid_off_the_lock_screen(self):
        import inspect
        src = inspect.getsource(A.Ringer._post_notification)
        self.assertIn("OTRV4PLUS_RING_PRIVACY", src)
        self.assertIn("Open Termux to answer", src)

    def test_helpers_are_argv_lists_never_a_shell(self):
        import inspect
        src = inspect.getsource(A.Ringer._spawn)
        self.assertNotIn("shell=True", src)


# ===========================================================================
# 2. the control channel
# ===========================================================================

class _ControlBase(unittest.TestCase):

    def setUp(self):
        if not hasattr(os, "mkfifo"):
            self.skipTest("no FIFO support on this platform")
        self.loop = asyncio.new_event_loop()
        self.addCleanup(self.loop.close)
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "call-ctl")
        self.dispatched = []
        self.chan = V.CallControlChannel(
            self.loop, path=self.path,
            which=lambda binary: "/bin/" + binary,
            dispatch=lambda *a: self.dispatched.append(a))
        self.addCleanup(self.chan.shutdown)
        self._termux = V._HOST.get("is_termux")
        V._HOST["is_termux"] = True
        self.addCleanup(lambda: V._HOST.__setitem__("is_termux", self._termux))

    def press(self, line):
        """Do what the notification button's shell command does."""
        with open(self.path, "w") as fifo:
            fifo.write(line + "\n")
        self.loop.run_until_complete(asyncio.sleep(0.05))

    def token_from(self, actions, verb="answer"):
        """Extract the token the way the FIFO will receive it."""
        marker = "printf '%s " % verb
        for _label, command in actions:
            if marker in command:
                return command.split(marker, 1)[1].split("\\n", 1)[0]
        raise AssertionError("no %s command in %r" % (verb, actions))


class TestControlChannel(_ControlBase):

    def test_unavailable_off_termux(self):
        V._HOST["is_termux"] = False
        self.assertFalse(self.chan.available())
        self.assertEqual(self.chan.arm(PEER, CALL_ID), [])
        self.assertFalse(os.path.exists(self.path),
                         "a non-Termux client must not create the FIFO")

    def test_unavailable_without_termux_api(self):
        self.chan._which = lambda binary: None
        self.assertFalse(self.chan.available())
        self.assertEqual(self.chan.arm(PEER, CALL_ID), [])

    def test_arming_creates_a_private_fifo(self):
        self.chan.arm(PEER, CALL_ID)
        self.assertTrue(stat.S_ISFIFO(os.stat(self.path).st_mode))
        mode = stat.S_IMODE(os.stat(self.path).st_mode)
        self.assertEqual(mode & 0o077, 0, "FIFO is readable by others")

    def test_the_command_carries_no_peer_text(self):
        actions = self.chan.arm("-rm -rf ~@evil.org", CALL_ID)
        for _label, command in actions:
            self.assertNotIn("evil", command)
            self.assertNotIn("rm", command)

    def test_the_command_passes_the_ringer_action_filter(self):
        for _label, command in self.chan.arm(PEER, CALL_ID):
            self.assertTrue(A.Ringer._action_ok(command),
                            "generated a command the ringer will reject: %r"
                            % command)

    def test_a_press_dispatches_once(self):
        actions = self.chan.arm(PEER, CALL_ID)
        self.press("answer " + self.token_from(actions))
        self.assertEqual(self.dispatched, [("answer", PEER, CALL_ID)])

    def test_decline_dispatches_decline(self):
        actions = self.chan.arm(PEER, CALL_ID)
        self.press("decline " + self.token_from(actions, "decline"))
        self.assertEqual(self.dispatched, [("decline", PEER, CALL_ID)])

    def test_a_replayed_press_is_ignored(self):
        actions = self.chan.arm(PEER, CALL_ID)
        token = self.token_from(actions)
        self.press("answer " + token)
        self.chan.arm(PEER, CALL_ID)          # ring again, new token
        self.press("answer " + token)
        self.assertEqual(len(self.dispatched), 1,
                         "a spent token answered a second call")

    def test_a_token_from_a_previous_call_cannot_answer_this_one(self):
        stale = self.token_from(self.chan.arm(PEER, CALL_ID))
        self.chan.disarm(PEER)
        self.chan.arm(PEER, OTHER_CALL_ID)
        self.press("answer " + stale)
        self.assertEqual(self.dispatched, [])

    def test_an_unknown_token_is_ignored(self):
        self.chan.arm(PEER, CALL_ID)
        self.press("answer " + "ff" * V.CallControlChannel.TOKEN_BYTES)
        self.assertEqual(self.dispatched, [])

    def test_an_unknown_verb_is_ignored(self):
        actions = self.chan.arm(PEER, CALL_ID)
        self.press("hangup " + self.token_from(actions))
        self.assertEqual(self.dispatched, [])

    def test_malformed_lines_are_ignored(self):
        actions = self.chan.arm(PEER, CALL_ID)
        token = self.token_from(actions)
        for junk in ("", "answer", "answer  extra bits",
                     "answer " + token[:-1], "answer " + token + "ff",
                     "\x00\x01\x02"):
            self.press(junk)
        self.assertEqual(self.dispatched, [])

    def test_a_flood_cannot_grow_the_buffer(self):
        self.chan.arm(PEER, CALL_ID)
        with open(self.path, "w") as fifo:
            fifo.write("x" * (V.CallControlChannel.MAX_BUFFER * 2))
        self.loop.run_until_complete(asyncio.sleep(0.05))
        self.assertLessEqual(len(self.chan._buffer),
                             V.CallControlChannel.MAX_BUFFER)
        self.assertEqual(self.dispatched, [])

    def test_an_expired_token_is_ignored(self):
        actions = self.chan.arm(PEER, CALL_ID)
        token = self.token_from(actions)
        peer, call_id, _expiry = self.chan._tokens[token]
        self.chan._tokens[token] = (peer, call_id, 0.0)
        self.press("answer " + token)
        self.assertEqual(self.dispatched, [])

    def test_tokens_are_bounded(self):
        for index in range(V.CallControlChannel.MAX_TOKENS + 4):
            self.chan.arm("peer%d@example.org" % index, CALL_ID)
        self.assertLessEqual(len(self.chan._tokens),
                             V.CallControlChannel.MAX_TOKENS)

    def test_disarm_removes_the_fifo(self):
        self.chan.arm(PEER, CALL_ID)
        self.chan.disarm(PEER)
        self.assertFalse(os.path.exists(self.path),
                         "the FIFO outlived the call it belonged to")

    def test_disarm_keeps_another_peers_channel_open(self):
        self.chan.arm(PEER, CALL_ID)
        self.chan.arm("carol@example.org", OTHER_CALL_ID)
        self.chan.disarm(PEER)
        self.assertTrue(os.path.exists(self.path))

    def test_close_is_idempotent(self):
        self.chan.arm(PEER, CALL_ID)
        self.chan.close()
        self.chan.close()

    def test_a_stale_regular_file_is_replaced(self):
        with open(self.path, "w") as handle:
            handle.write("left over")
        self.chan.arm(PEER, CALL_ID)
        self.assertTrue(stat.S_ISFIFO(os.stat(self.path).st_mode))

    def test_a_shell_unsafe_path_yields_no_buttons(self):
        self.chan.close()
        self.chan.path = os.path.join(self.dir, "call ctl; rm -rf ~")
        self.assertEqual(self.chan.arm(PEER, CALL_ID), [])

    def test_the_generated_command_actually_works_in_a_shell(self):
        """The whole loop, with a real /bin/sh standing in for Termux.

        Everything else here tests a piece. This runs the exact string that
        goes into --button1-action through a shell, as the Termux app will,
        and checks the client answers the call.
        """
        import subprocess
        actions = self.chan.arm(PEER, CALL_ID)
        command = [c for label, c in actions if label == "Answer"][0]
        subprocess.run(["/bin/sh", "-c", command], timeout=10, check=True)
        self.loop.run_until_complete(asyncio.sleep(0.05))
        self.assertEqual(self.dispatched, [("answer", PEER, CALL_ID)])

    def test_the_command_is_inert_once_the_client_has_gone(self):
        """The same string after teardown: no dispatch, no stray file."""
        import subprocess
        actions = self.chan.arm(PEER, CALL_ID)
        command = [c for label, c in actions if label == "Answer"][0]
        self.chan.shutdown()
        subprocess.run(["/bin/sh", "-c", command], timeout=10)
        self.assertFalse(os.path.exists(self.path),
                         "a dead button left a stray file behind")
        self.assertEqual(self.dispatched, [])

    def test_the_command_is_a_no_op_when_the_client_is_gone(self):
        # `test -p` first, so a button pressed after the client exited neither
        # creates a stray file nor blocks on a pipe nobody reads.
        for _label, command in self.chan.arm(PEER, CALL_ID):
            self.assertTrue(command.startswith("test -p "))


# ===========================================================================
# 3. the state machine sees a button exactly as it sees /answer
# ===========================================================================

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


class TestControlCommandGating(unittest.TestCase):

    def setUp(self):
        self.loop = asyncio.new_event_loop()
        self.addCleanup(self.loop.close)
        self.mgr = V.VoiceCallManager(_Client(), self.loop)
        self.addCleanup(self.mgr._call_control.shutdown)
        self.session = V.VoiceCallSession(PEER, self.loop, CALL_ID, False)
        self.session.otr_material = (b"OTRv4+Voice/session/v3",
                                     "AA" * 64, "BB" * 64)
        self.session.transition(V.CallState.RINGING)
        self.mgr._calls[PEER] = self.session
        self.calls = []
        self.mgr.answer_call = self._record("answer")
        self.mgr.reject_call = self._record("reject")

    def _record(self, name):
        async def _coro(peer):
            self.calls.append((name, peer))
        return _coro

    def run_pending(self):
        for _ in range(4):
            self.loop.run_until_complete(asyncio.sleep(0))

    def test_answer_takes_the_ordinary_path(self):
        self.mgr._on_control_command("answer", PEER, CALL_ID)
        self.run_pending()
        self.assertEqual(self.calls, [("answer", PEER)])

    def test_decline_takes_the_ordinary_path(self):
        self.mgr._on_control_command("decline", PEER, CALL_ID)
        self.run_pending()
        self.assertEqual(self.calls, [("reject", PEER)])

    def test_a_press_for_a_different_call_id_does_nothing(self):
        self.mgr._on_control_command("answer", PEER, OTHER_CALL_ID)
        self.run_pending()
        self.assertEqual(self.calls, [])

    def test_a_press_for_an_unknown_peer_does_nothing(self):
        self.mgr._on_control_command("answer", "carol@example.org", CALL_ID)
        self.run_pending()
        self.assertEqual(self.calls, [])

    def test_a_press_after_the_call_moved_on_does_nothing(self):
        for state in (V.CallState.CONNECTING, V.CallState.KEY_CONFIRMING,
                      V.CallState.MEDIA_CONNECTING, V.CallState.ACTIVE,
                      V.CallState.ENDED):
            self.session.state = state
            self.mgr._on_control_command("answer", PEER, CALL_ID)
        self.run_pending()
        self.assertEqual(self.calls, [],
                         "a notification press acted on a call that was no "
                         "longer ringing")

    def test_the_button_never_bypasses_the_smp_gate(self):
        # The gate lives upstream: _on_invite refuses to allocate a session,
        # and therefore to ring, unless SMP verified the peer. A button can
        # only ever act on a session that already exists.
        import inspect
        src = inspect.getsource(V.VoiceCallManager._on_invite)
        self.assertIn("_smp_verified(peer)", src)
        self.assertLess(src.index("_smp_verified"), src.index("_start_ringing"),
                        "ringing must be downstream of the SMP check")
        handler = inspect.getsource(V.VoiceCallManager._on_control_command)
        self.assertIn("self._calls.get(peer)", handler)
        self.assertIn("CallState.RINGING", handler)

    def test_the_button_only_ever_calls_the_public_entry_points(self):
        import inspect
        src = inspect.getsource(V.VoiceCallManager._on_control_command)
        self.assertIn("self.answer_call(peer)", src)
        self.assertIn("self.reject_call(peer)", src)
        for forbidden in ("transition(", "_signal(", "responder_derive",
                          "schedule", "create_session"):
            self.assertNotIn(forbidden, src,
                             "the button reaches past the call API: %s"
                             % forbidden)


class TestRingLifecycle(unittest.TestCase):

    def setUp(self):
        self.loop = asyncio.new_event_loop()
        self.addCleanup(self.loop.close)
        self.mgr = V.VoiceCallManager(_Client(), self.loop)
        self.addCleanup(self.mgr._call_control.shutdown)

    def test_stopping_the_ring_revokes_the_buttons(self):
        import inspect
        src = inspect.getsource(V.VoiceCallManager._stop_ringing)
        self.assertIn("_call_control.disarm(peer)", src)

    def test_every_exit_from_ringing_stops_the_ring(self):
        import inspect
        for name in ("answer_call", "reject_call", "end_call"):
            src = inspect.getsource(getattr(V.VoiceCallManager, name))
            self.assertIn("_stop_ringing(peer)", src,
                          "%s leaves the notification ringing" % name)

    def test_teardown_closes_the_channel(self):
        import inspect
        for name in ("cleanup", "cleanup_sync"):
            src = inspect.getsource(getattr(V.VoiceCallManager, name))
            self.assertIn("_call_control.shutdown()", src)

    def test_a_ringer_failure_never_stops_a_call_arriving(self):
        import inspect
        src = inspect.getsource(V.VoiceCallManager._start_ringing)
        self.assertEqual(src.count("except Exception"), 2,
                         "both the buttons and the tone must be best-effort")


if __name__ == "__main__":
    unittest.main(verbosity=2)
