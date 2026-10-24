# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Terminal sounds and one-key y/n answers (otrv4plus_alerts).

Owner (2026-10-14): "simple prompts y/n for accepting for end users, less
typing in terminal the better" and "Notification sounds for incoming
messages, calls etc".
"""
from __future__ import annotations

from source_of import voice_source  # noqa: E402
import io
import pathlib

import otrv4plus_alerts as A

ROOT = pathlib.Path(__file__).resolve().parent.parent


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


class Tty(io.StringIO):
    def isatty(self):
        return True


# -- QuickAnswer ---------------------------------------------------------------

def test_a_bare_y_or_n_answers_the_open_question_once():
    q = A.QuickAnswer(clock=Clock())
    said = []
    q.ask("file", lambda: said.append("yes"), lambda: said.append("no"))
    assert q.pending() == "file"
    assert q.answer("  Y ") is True
    assert said == ["yes"]
    assert q.answer("y") is False            # answered: nothing open
    q.ask("call", lambda: said.append("yes"), lambda: said.append("no"))
    assert q.answer("no") is True
    assert said == ["yes", "no"]


def test_anything_but_an_exact_y_or_n_is_typed_as_usual():
    q = A.QuickAnswer(clock=Clock())
    q.ask("file", lambda: None, lambda: None)
    for line in ("yeah", "y please", "/answer", "", "nope"):
        assert q.answer(line) is False
    assert q.pending() == "file"


def test_the_question_lapses_when_its_subject_is_gone_or_it_is_old():
    clock = Clock()
    q = A.QuickAnswer(clock=clock)
    ringing = [True]
    q.ask("call", lambda: None, lambda: None, still_open=lambda: ringing[0])
    ringing[0] = False                       # the caller hung up
    assert q.answer("y") is False and q.pending() is None
    q.ask("file", lambda: None, lambda: None)
    clock.t += A.QuickAnswer.SECONDS + 1
    assert q.answer("y") is False


def test_the_newest_question_wins_and_tells_the_other_system():
    dropped = []
    q = A.QuickAnswer(clock=Clock(), on_ask=lambda: dropped.append(1))
    said = []
    q.ask("file", lambda: said.append("file"), lambda: None)
    q.ask("call", lambda: said.append("call"), lambda: None)
    assert q.answer("y") and said == ["call"]
    assert dropped == [1, 1]


# -- Alerts --------------------------------------------------------------------

def _alerts(clock, ran, termux=True, out=None):
    return A.Alerts(out=out or Tty(), clock=clock, run=ran.append,
                    which=lambda b: ("/bin/" + b) if termux else None,
                    enabled=True)


def test_a_message_rings_the_bell_and_posts_a_content_free_notification():
    ran, out = [], Tty()
    a = _alerts(Clock(), ran, out=out)
    a.message()
    assert out.getvalue() == "\a"
    assert len(ran) == 1
    argv = ran[0]
    assert argv[0] == "termux-notification"
    assert argv[argv.index("--content") + 1] == "New message"
    assert argv[argv.index("--title") + 1] == "Off The Record v4 Plus"


def test_a_burst_is_one_sound_and_the_count_shows_next_time():
    clock, ran = Clock(), []
    a = _alerts(clock, ran)
    for _ in range(5):
        a.message()
    assert len(ran) == 1
    clock.t += A.Alerts.MESSAGE_GAP + 0.1
    a.message()
    assert ran[-1][ran[-1].index("--content") + 1] == "6 new messages"


def test_typing_clears_the_count_and_the_notification():
    clock, ran = Clock(), []
    a = _alerts(clock, ran)
    a.message()
    a.seen()
    assert ran[-1] == ["termux-notification-remove", A.Alerts.NOTIFICATION_ID]
    n = len(ran)
    a.seen()                                 # nothing unseen: no process
    assert len(ran) == n


def test_quiet_means_quiet_and_no_termux_means_bell_only():
    ran, out = [], Tty()
    a = A.Alerts(out=out, clock=Clock(), run=ran.append,
                 which=lambda b: "/bin/" + b, enabled=False)
    a.message()
    a.ring_once()
    assert ran == [] and out.getvalue() == ""
    out2 = Tty()
    b = _alerts(Clock(), ran, termux=False, out=out2)
    b.message()
    assert ran == [] and out2.getvalue() == "\a"


def test_a_group_call_rings_once():
    ran, out = [], Tty()
    a = _alerts(Clock(), ran, out=out)
    a.ring_once()
    assert out.getvalue() == "\a\a"
    assert ran[0][ran[0].index("--content") + 1] == "Incoming call"


def test_the_bell_is_not_written_into_a_pipe():
    ran, out = [], io.StringIO()            # not a terminal
    _alerts(Clock(), ran, out=out).message()
    assert out.getvalue() == ""


# -- wiring --------------------------------------------------------------------

def test_the_client_answers_calls_and_files_with_y_n_and_sounds_messages():
    src = (ROOT / "client" / "otrv4plus_xmpp.py").read_text()
    assert "quick().answer(line)" in src
    assert "on_state=self._on_file_state" in src and "quick_answer=True" in src
    assert "self._alerts().message()" in src
    assert '"/sound on"' in src
    # The y/n check sits before group questions and before command parsing.
    import inspect
    import otrv4plus_xmpp
    cls = otrv4plus_xmpp.OTRv4PlusXMPP
    pending = inspect.getsource(cls._dispatch_pending)
    assert pending.index("quick().answer(line)") < pending.index("groups.answer_prompt(line)")
    dispatch = inspect.getsource(cls.dispatch_line)
    assert dispatch.index("_dispatch_pending(line)") < dispatch.index('if lstrip == "/tui":')
    voice = voice_source()
    assert 'getattr(self.client, "ask_answer_call", None)' in voice
    assert "Answer? [y/n]" in voice


def test_nothing_a_peer_sent_reaches_the_notification():
    src = (ROOT / "client" / "otrv4plus_alerts.py").read_text()
    body = src[src.index("    def _notify("):src.index("    @staticmethod")]
    assert '"--content", content' in body
    # The only contents are fixed strings and a count.
    calls = [line for line in src.splitlines() if "self._notify(" in line]
    for line in calls:
        assert "peer" not in line and "body" not in line


def test_a_1to1_file_offer_is_answered_with_y_or_n():
    import types

    import pytest
    pytest.importorskip("slixmpp")
    X = pytest.importorskip("otrv4plus_xmpp")
    from xmpp_double import bare_client

    c = bare_client(X.OTRv4PlusXMPP)
    tid = bytes.fromhex("ab" * 16)
    transfer = types.SimpleNamespace(
        state=X._filetransfer.TransferState.OFFERED, accepted=False,
        offer=types.SimpleNamespace(transfer_id=tid))
    c._file_manager = types.SimpleNamespace(incoming={tid.hex(): transfer})
    ran = []
    c._cmd_transfer = ran.append
    c._alerts_obj = A.Alerts(out=io.StringIO(), run=lambda argv: None,
                             which=lambda b: None, enabled=True)
    c._on_file_state(transfer, False)
    assert c._quick_answer().pending() == "file"
    assert c._quick_answer().answer("y")
    assert ran == ["accept abababab"]
    # Once accepted (or cancelled by the sender) a y is just a y.
    c._on_file_state(transfer, False)
    transfer.accepted = True
    assert c._quick_answer().answer("n") is False
    # An outgoing transfer never asks.
    c._on_file_state(transfer, True)
    assert c._quick_answer().pending() is None
