#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Signing out really signs out, including the OTR engine.

TWO DEFECTS, ONE CONSEQUENCE
============================
1. `clear_all_sessions` did not clear sessions. It looped over
   `terminate_session`, whose own limitation is documented thirty lines above
   it: that method "terminates the session object but leaves the entry in
   `self.sessions`, so the next `get_or_create_session` hands back the dead
   one". Measured through the Android facade before the fix:

       after OtrApp.shutdown()          : ENCRYPTED
       engine has_session('bob@x.test') : True

2. Nothing called `shutdown()` at all. It existed on `ChaquopyOtrCore` with
   no caller anywhere in the app. `OtrConnectionService`'s ACTION_LOGOUT
   cleared the credentials, the message history, the chat state and the
   notification badge -- and never told the engine.

Together: sessions are keyed by PEER JID, so after a logout a second account
signing in on the same device inherited the first account's live encrypted
session with any shared contact. Account B would have been sending under
account A's OTR session.

WHAT IS DELIBERATELY NOT CLEARED
================================
The trust database. A pinned fingerprint is long-term identity about a PEER,
not about whichever account pinned it, and discarding it on logout would turn
the next conversation into a fresh trust-on-first-use decision -- which is the
exact moment TOFU exists to make visible. Asserted below so a future "clear
everything on logout" cannot quietly take it.
"""

import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

otr = pytest.importorskip("otrv4_")
pytest.importorskip("otrv4_core")

from android_bridge.app import OtrApp, Transport                # noqa: E402
from android_bridge.events import SecurityState                 # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SERVICE_KT = os.path.join(
    ROOT, "android", "app", "src", "main", "java", "org", "otrv4plus",
    "android", "connection", "OtrConnectionService.kt")

PEER = "bob@example.test"


def _launch_bodies(source, call):
    """The block each `<call> {` opens, by brace depth.

    Counting braces rather than matching a closing indent, because the blocks
    nest (`withContext` inside `launch`) and an indent-based reader stops at
    the first inner `}`.
    """
    bodies = []
    start = source.find(call)
    while start != -1:
        i = source.index("{", start)
        depth, j = 0, i
        while j < len(source):
            if source[j] == "{":
                depth += 1
            elif source[j] == "}":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        bodies.append(source[i:j + 1])
        start = source.find(call, j)
    return bodies


class Wire(Transport):
    def __init__(self):
        self.sent = []
        self.peer_app = None
        self.peer_id = None

    def send(self, peer, payload):
        text = (payload.decode("utf-8", errors="replace")
                if isinstance(payload, (bytes, bytearray)) else str(payload))
        self.sent.append((peer, text))
        if self.peer_app is not None:
            self.peer_app.receive_message(self.peer_id, text)

    def connect(self): pass
    def disconnect(self): pass
    def roster(self): return []


def _manager():
    directory = tempfile.mkdtemp()
    config = otr.OTRConfig(test_mode=True)
    for attribute, name in (("trust_db_path", "trust.json"),
                            ("smp_secrets_path", "smp.json"),
                            ("key_storage_path", "keys")):
        if hasattr(config, attribute):
            setattr(config, attribute, os.path.join(directory, name))
    return otr.EnhancedSessionManager(config=config)


@pytest.fixture
def established():
    """One Android bridge with a real encrypted session to PEER."""
    otr._dake1_rate_limiter._attempts.clear()
    local_wire, peer_wire = Wire(), Wire()
    local = OtrApp(_manager(), local_wire)
    peer = OtrApp(_manager(), peer_wire)
    local_wire.peer_app, local_wire.peer_id = peer, "me@example.test"
    peer_wire.peer_app, peer_wire.peer_id = local, PEER

    local.start_session(PEER)
    assert local.security_state(PEER) is not SecurityState.PLAINTEXT, \
        "the fixture did not establish a session"
    return local


class TestShutdownActuallyTearsDown:

    def test_the_session_is_gone_after_shutdown(self, established):
        assert established._engine.has_session(PEER) is True
        established.shutdown()
        assert established._engine.has_session(PEER) is False, (
            "clear_all_sessions left the entry in place, so the next "
            "get_or_create_session hands back the dead one")

    def test_the_security_state_drops_to_plaintext(self, established):
        established.shutdown()
        assert established.security_state(PEER) is SecurityState.PLAINTEXT, (
            "the facade still reports an encrypted session after shutdown")

    def test_the_session_table_is_empty(self, established):
        established.shutdown()
        assert dict(established._engine.sessions) == {}
        assert dict(established._engine.dake_engines) == {}

    def test_a_second_account_does_not_inherit_the_session(self, established):
        """THE SECURITY CONSEQUENCE. Sessions are keyed by peer JID, so
        without a real teardown the next account to sign in on this device
        would find account A's encrypted session with a shared contact
        already in place."""
        engine = established._engine
        established.shutdown()

        # Account B, same process, same engine object -- which is what the
        # service holds across a logout/login without a process restart.
        successor = OtrApp(engine)
        assert successor.security_state(PEER) is SecurityState.PLAINTEXT, (
            "a new account inherited the previous account's OTR session")
        assert successor._engine.has_session(PEER) is False

    def test_shutdown_is_safe_to_call_twice(self, established):
        established.shutdown()
        established.shutdown()          # must not raise
        assert established._engine.has_session(PEER) is False

    def test_shutdown_with_no_sessions_is_harmless(self):
        OtrApp(_manager()).shutdown()   # must not raise

    def test_the_trust_database_survives(self, established):
        """Deliberately kept. A pinned fingerprint is identity about a PEER,
        and forgetting it would make the next conversation a fresh TOFU
        decision -- the moment this project most wants to be visible."""
        engine = established._engine
        stored = engine.trust_db.get_trusted_fingerprints() \
            if hasattr(engine.trust_db, "get_trusted_fingerprints") else None
        established.shutdown()
        if stored is not None:
            assert engine.trust_db.get_trusted_fingerprints() == stored, (
                "logout discarded pinned fingerprints; the next conversation "
                "becomes a fresh trust-on-first-use decision")

    def test_a_fresh_dake_still_works_afterwards(self, established):
        """Teardown must leave the engine usable, not wedged. `end_session`
        exists precisely because `terminate_session` left a dead entry that
        blocked the next handshake."""
        engine = established._engine
        established.shutdown()

        otr._dake1_rate_limiter._attempts.clear()
        local_wire, peer_wire = Wire(), Wire()
        local = OtrApp(engine, local_wire)
        peer = OtrApp(_manager(), peer_wire)
        local_wire.peer_app, local_wire.peer_id = peer, "me@example.test"
        peer_wire.peer_app, peer_wire.peer_id = local, PEER

        local.start_session(PEER)
        assert local.security_state(PEER) is not SecurityState.PLAINTEXT, (
            "the engine could not establish a new session after a teardown")


class TestTheEngineIsToldOnLogout:
    """The Kotlin half. Compose and Android services cannot run here, so the
    wiring is asserted structurally -- the behaviour it protects is driven
    above."""

    @staticmethod
    @pytest.fixture(scope="class")
    def logout_branch():
        source = open(SERVICE_KT, encoding="utf-8").read()
        start = source.index("ACTION_LOGOUT ->")
        return source[start:source.index("ACTION_START ->", start)]

    def test_logout_tears_the_engine_down(self, logout_branch):
        assert "core.shutdown()" in logout_branch, (
            "logout clears the credentials, the history and the chat state "
            "and never tells the engine, so its sessions outlive the account")

    def test_the_teardown_is_off_the_main_thread(self, logout_branch):
        """It crosses into Python and terminates sessions."""
        assert "Dispatchers.IO" in logout_branch

    def test_the_teardown_is_not_racing_the_thing_that_cancels_it(
            self, logout_branch):
        """THE RACE, and it loses the fix above when it goes the wrong way.

        The branch launches the teardown and then calls `stopSelf()`, which
        leads to `onDestroy`, which calls `scope.cancel()`. A coroutine
        started on the service's own scope is therefore racing the
        cancellation of that scope -- and if cancellation wins,
        `core.shutdown()` never runs and the engine keeps the signed-out
        account's sessions for the next account to inherit.
        """
        source = open(SERVICE_KT, encoding="utf-8").read()
        destroy = source[source.index("override fun onDestroy()"):]
        destroy = destroy[:destroy.index("super.onDestroy()")]
        assert "scope.cancel()" in destroy, (
            "this test is about a race with onDestroy's cancellation and "
            "cannot find it; re-establish what it is protecting")
        # `rindex` for the call: the comment above the teardown names
        # `stopSelf()` in prose, and `index` matches the sentence rather than
        # the statement.
        assert logout_branch.rindex("stopSelf()") > \
            logout_branch.index("core.shutdown()"), \
            "the teardown is started after the service is told to stop"
        assert "scope.launch" not in logout_branch, (
            "the engine teardown runs on the service scope that stopSelf() "
            "is about to cancel")
        assert "teardown.launch" in logout_branch

    def test_the_surviving_scope_is_only_used_for_teardown(self):
        """It is an escape from the service lifecycle, so it stays narrow.

        A connect ATTEMPT outliving its service would be I2P tunnels nobody
        is watching -- the failure this exists to prevent, not to cause. So
        the two uses are named: the engine shutdown on logout, and the
        connection teardown. A third would have to argue with this line.
        """
        source = open(SERVICE_KT, encoding="utf-8").read()
        assert source.count("teardown.launch") == 2, (
            "the scope that outlives the service grew a new use; it carries "
            "teardown and nothing else")
        for body in _launch_bodies(source, "teardown.launch"):
            assert "core.shutdown()" in body or "core.disconnect()" in body, (
                "something that is not a teardown was put on the scope that "
                "outlives the service:\n%s" % body)

    def test_the_connection_teardown_is_not_racing_its_own_cancellation(self):
        """`stopConnection` is followed by the end of the service on every
        path that matters: ACTION_STOP and ACTION_LOGOUT call `stopSelf()`,
        and `onDestroy` calls `scope.cancel()` two lines later. Launched on
        `scope`, the disconnect can be cancelled before it runs, leaving the
        transport's worker thread, its authenticated stream and its I2P
        tunnel alive with nothing holding a reference that could close them.
        """
        source = open(SERVICE_KT, encoding="utf-8").read()
        body = source[source.index("fun stopConnection("):]
        body = body[:body.index("\n    }")]
        assert "core.disconnect()" in body, (
            "this test cannot find the disconnect it is about")
        assert "scope.launch" not in body, (
            "the connection teardown runs on the scope that onDestroy is "
            "about to cancel")
        assert "teardown.launch" in body

    def test_logout_still_clears_everything_it_did_before(self, logout_branch):
        """The engine teardown is an addition, not a replacement."""
        for cleared in ("credentials.clear()", "messages.forgetAccount()",
                        "enterAccount(AccountScope.NONE)", "alerts.clear()"):
            assert cleared in logout_branch, "logout no longer does %s" % cleared

    def test_an_ordinary_disconnect_does_not_tear_the_engine_down(self):
        """Only LOGOUT forgets. Pressing Disconnect, or a dropped stream,
        must not destroy sessions the user has not asked to forget."""
        source = open(SERVICE_KT, encoding="utf-8").read()
        stop = source[source.index("ACTION_STOP ->"):]
        stop = stop[:stop.index("ACTION_LOGOUT ->")]
        assert "core.shutdown()" not in stop, (
            "ACTION_STOP destroys the engine; a disconnect is not a logout")
