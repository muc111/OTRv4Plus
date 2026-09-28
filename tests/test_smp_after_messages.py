# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""SMP started after ordinary encrypted chat, through two real bridges.

Device report: after a few ordinary messages, starting verification put a
blank message from the contact into the conversation on both sides. SMP
travels as TLVs on a data message with empty text; `receive_message` handed
that empty text to the UI as a `MessageReceived`. SMP must stay a distinct
protocol operation: no blank bubble, correct secret verifies, wrong secret
fails, and the session carries on afterwards.
"""
import pytest

pytest.importorskip("otrv4_")
pytest.importorskip("otrv4_core")

from android_bridge.events import MessageReceived, SmpState   # noqa: E402
from tests.test_wipe_and_exit import (SECRET, _pair,           # noqa: E402,F401
                                      isolated_home)


@pytest.fixture
def chatting():
    p = _pair()
    p.alice.start_session(p.bob_jid)
    for i in range(4):
        p.alice.send_user_text(p.bob_jid, "hello %d" % i)
        p.bob.send_user_text(p.alice_jid, "reply %d" % i)
    yield p
    for app in (p.alice, p.bob):
        try:
            app.shutdown()
        except Exception:
            pass


def _received(sink):
    return [e.body for e in sink.events if isinstance(e, MessageReceived)]


def test_ordinary_messages_arrive_before_smp(chatting):
    assert _received(chatting.bob_sink) == ["hello %d" % i for i in range(4)]
    assert _received(chatting.alice_sink) == ["reply %d" % i for i in range(4)]


def test_smp_after_messages_verifies_and_adds_no_message(chatting):
    p = chatting
    before_a, before_b = len(_received(p.alice_sink)), len(_received(p.bob_sink))
    p.alice.smp_start(p.bob_jid, SECRET)
    p.bob.smp_respond(p.alice_jid, SECRET)
    assert p.alice.smp_state(p.bob_jid) is SmpState.VERIFIED
    assert p.bob.smp_state(p.alice_jid) is SmpState.VERIFIED
    assert len(_received(p.alice_sink)) == before_a, _received(p.alice_sink)
    assert len(_received(p.bob_sink)) == before_b, _received(p.bob_sink)
    assert "" not in _received(p.alice_sink) + _received(p.bob_sink)


def test_wrong_secret_fails_after_messages(chatting):
    p = chatting
    p.alice.smp_start(p.bob_jid, SECRET)
    p.bob.smp_respond(p.alice_jid, "a different secret entirely")
    assert p.alice.smp_state(p.bob_jid) is SmpState.FAILED
    assert p.alice.smp_state(p.bob_jid) is not SmpState.VERIFIED
    assert p.bob.smp_state(p.alice_jid) is not SmpState.VERIFIED
    assert "" not in _received(p.alice_sink) + _received(p.bob_sink)


def test_messages_continue_after_smp(chatting):
    p = chatting
    p.alice.smp_start(p.bob_jid, SECRET)
    p.bob.smp_respond(p.alice_jid, SECRET)
    p.alice.send_user_text(p.bob_jid, "after verification")
    p.bob.send_user_text(p.alice_jid, "still here")
    assert _received(p.bob_sink)[-1] == "after verification"
    assert _received(p.alice_sink)[-1] == "still here"
    assert "" not in _received(p.alice_sink) + _received(p.bob_sink)


def test_a_second_run_on_a_verified_session_is_refused_with_a_reason(chatting):
    from android_bridge.app import BridgeError
    p = chatting
    p.alice.smp_start(p.bob_jid, SECRET)
    p.bob.smp_respond(p.alice_jid, SECRET)
    with pytest.raises(BridgeError) as e:
        p.bob.smp_start(p.alice_jid, SECRET)
    assert e.value.code == "smp_already_verified"
    # Nothing was thrown away by asking.
    assert p.alice.smp_state(p.bob_jid) is SmpState.VERIFIED
    assert p.bob.smp_state(p.alice_jid) is SmpState.VERIFIED


def test_a_retry_inside_the_cooldown_says_so(chatting):
    from android_bridge.app import BridgeError
    p = chatting
    p.alice.smp_start(p.bob_jid, SECRET)
    p.bob.smp_respond(p.alice_jid, "a different secret entirely")
    with pytest.raises(BridgeError) as e:
        p.alice.smp_start(p.bob_jid, SECRET)
    assert e.value.code == "smp_cooldown"


@pytest.mark.parametrize("retrier", ["initiator", "responder"])
def test_a_failed_run_can_be_retried_after_the_cooldown(chatting, retrier, monkeypatch):
    """Before the fix a failed run was terminal for the session.

    The responder's engine refused SMP1 outside Idle, and the Python race
    path ignored it outright on the side with the lower fingerprint.
    """
    import time
    p = chatting
    p.alice.smp_start(p.bob_jid, SECRET)
    p.bob.smp_respond(p.alice_jid, "a different secret entirely")
    assert p.alice.smp_state(p.bob_jid) is SmpState.FAILED
    time.sleep(31)                       # the Rust cooldown, not shortened
    first, second = (p.alice, p.bob) if retrier == "initiator" else (p.bob, p.alice)
    first_peer, second_peer = ((p.bob_jid, p.alice_jid) if retrier == "initiator"
                               else (p.alice_jid, p.bob_jid))
    first.smp_start(first_peer, SECRET)
    assert second.smp_secret_required(second_peer), "the retry was not delivered"
    second.smp_respond(second_peer, SECRET)
    assert first.smp_state(first_peer) is SmpState.VERIFIED
    assert second.smp_state(second_peer) is SmpState.VERIFIED
    assert "" not in _received(p.alice_sink) + _received(p.bob_sink)
