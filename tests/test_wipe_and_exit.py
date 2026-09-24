#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Enforces INV-28: Wipe & Exit destroys every session secret, and nothing
it destroyed can be used again.

Driven against real engines: two `OtrApp`s with a live OTR session between
them, a real SMP run, real transfers keyed by the Rust core, and a real voice
key schedule. The destruction is checked by asking the Rust objects
themselves -- a ratchet's state tags, a handle's `destroyed`, a transfer key's
`zeroized`, a voice root's `spent` -- WHILE THE TEST STILL HOLDS A REFERENCE
to each. That is the point: a wipe that relied on the garbage collector would
leave every one of them intact, because the test is the reference that keeps
them alive.

What a test cannot prove is that no copy of a key survives anywhere in
process memory. That is the Rust core's `ZeroizeOnDrop` contract, exercised
by the Rust unit tests; here the claim is that the wipe INVOKES it, for every
object, on the right thread.

Every test runs under a temporary HOME. The wipe deletes `~/.otrv4plus`, and
a test must never be able to reach the real one.
"""

import os
import tempfile
import threading
import time
import uuid

import pytest

otr = pytest.importorskip("otrv4_")
core = pytest.importorskip("otrv4_core")
voice = pytest.importorskip("otrv4plus_voice")

from android_bridge.app import OtrApp, Transport                  # noqa: E402
from android_bridge.events import SecurityState, SmpState         # noqa: E402
from android_bridge.files import FileOutcome                      # noqa: E402
from android_bridge.voice import CallOutcome                      # noqa: E402

SECRET = "a shared secret we both know"


@pytest.fixture(autouse=True)
def isolated_home(monkeypatch):
    home = tempfile.mkdtemp(prefix="wipe-home-")
    monkeypatch.setenv("HOME", home)
    monkeypatch.delenv("OTRV4PLUS_FILE_DIR", raising=False)
    yield home


@pytest.fixture
def audio_available(monkeypatch):
    # Imported FIRST. Its import binds the real host hooks -- including
    # `voice_available`, which says this container has no audio -- and the
    # call bridge imports it on first use. Overriding before that import
    # meant the first test to build a call manager lost the override, so the
    # INVITE was refused as "unavailable" before it reached the SMP gate and
    # the gate tests passed or failed depending on which test ran first.
    import otrv4plus_xmpp                                    # noqa: F401
    previous = voice._HOST["voice_available"]
    voice.bind_host(voice_available=lambda: (True, "ok"))
    yield
    voice._HOST["voice_available"] = previous


class Sink:
    def __init__(self):
        self.events = []

    def on_event(self, event):
        self.events.append(event)


class Wire(Transport):
    """Delivers one bridge's output into the other; can be cut."""

    def __init__(self):
        self.peer_app = None
        self.peer_id = None
        self.cut = False
        self.closed = False
        self.loop_thread_calls = []

    def send(self, peer, payload):
        text = (payload.decode("utf-8", errors="replace")
                if isinstance(payload, (bytes, bytearray)) else str(payload))
        if self.peer_app is not None and not self.cut:
            self.peer_app.receive_message(self.peer_id, text)

    def connect(self): pass
    def disconnect(self): pass
    def roster(self): return []

    def close(self):
        self.closed = True


class LoopWire(Wire):
    """A wire with a real loop thread of its own.

    Stands in for `XmppTransport`: inbound OTR is processed on ONE worker
    thread, so the DAKE objects are created there -- as on a device -- and
    `run_on_loop_thread` runs work on that same thread. The test can then see
    which thread the wipe used, and PyO3 enforces that it was the right one.
    """

    def __init__(self):
        super().__init__()
        from concurrent.futures import ThreadPoolExecutor
        self._worker = ThreadPoolExecutor(max_workers=1,
                                          thread_name_prefix="fake-loop")
        self.loop_ident = self._worker.submit(threading.get_ident).result()
        self.ran_on = None

    def run_on_loop_thread(self, fn, timeout=30.0):
        def run():
            self.ran_on = threading.get_ident()
            return fn()
        return self._worker.submit(run).result(timeout)

    def close(self):
        super().close()


def _manager():
    directory = tempfile.mkdtemp()
    config = otr.OTRConfig(test_mode=True)
    for attribute, name in (("trust_db_path", "trust.json"),
                            ("smp_secrets_path", "smp.json"),
                            ("key_storage_path", "keys")):
        setattr(config, attribute, os.path.join(directory, name))
    return otr.EnhancedSessionManager(config=config)


class Pair:
    pass


def _pair(alice_wire=None):
    p = Pair()
    p.alice_jid = "alice-%s@example.test" % uuid.uuid4().hex[:8]
    p.bob_jid = "bob-%s@example.test" % uuid.uuid4().hex[:8]
    otr._dake1_rate_limiter._attempts.clear()
    p.alice_wire, p.bob_wire = alice_wire or Wire(), Wire()
    p.alice_sink, p.bob_sink = Sink(), Sink()
    p.alice = OtrApp(_manager(), p.alice_wire, p.alice_sink)
    p.bob = OtrApp(_manager(), p.bob_wire, p.bob_sink)
    p.alice_wire.peer_app, p.alice_wire.peer_id = p.bob, p.alice_jid
    p.bob_wire.peer_app, p.bob_wire.peer_id = p.alice, p.bob_jid
    return p


@pytest.fixture
def pair():
    p = _pair()
    p.alice.start_session(p.bob_jid)
    assert p.alice.security_state(p.bob_jid) is not SecurityState.PLAINTEXT
    yield p
    for app in (p.alice, p.bob):
        try:
            app.shutdown()
        except Exception:
            pass


@pytest.fixture
def verified(pair):
    pair.alice.smp_start(pair.bob_jid, SECRET)
    pair.bob.smp_respond(pair.alice_jid, SECRET)
    assert pair.alice.smp_state(pair.bob_jid) is SmpState.VERIFIED
    return pair


def _dummy_tags():
    """The state tags of the placeholder `RustDoubleRatchet.zeroize` leaves.

    `zeroize` replaces the ratchet's keys with fixed dummies and drops the
    real ones (ZeroizeOnDrop). A ratchet whose tags equal these has had its
    keys destroyed; one whose tags differ has not.
    """
    r = core.RustDoubleRatchet(b"\x01" * 32, b"\x02" * 32, b"\x03" * 32,
                               b"\x04" * 32, b"\x05" * 56, False)
    return {k: bytes(v) for k, v in r.state_tags().items()}


def _tags(rust_ratchet):
    return {k: bytes(v) for k, v in rust_ratchet.state_tags().items()}


# ---------------------------------------------------------------------------
# The Rust objects are destroyed, not merely dropped
# ---------------------------------------------------------------------------

class TestTheSecretsAreDestroyedInRust:

    def test_the_ratchet_keys_are_destroyed_while_a_reference_survives(self, pair):
        session = pair.alice._engine.sessions[pair.bob_jid]
        leaked_rust = session.ratchet._rust          # the "leaked" reference
        leaked_dh = session.ratchet.dh_ratchet_local
        assert _tags(leaked_rust) != _dummy_tags()

        pair.alice.wipe()

        assert _tags(leaked_rust) == _dummy_tags(), (
            "the ratchet still holds its keys: the wipe relied on the last "
            "reference going, and the test is holding it")
        assert leaked_dh.destroyed

    def test_the_identity_keys_are_destroyed(self, pair):
        profile = pair.alice._engine.client_profile
        identity, prekey = profile.identity_key, profile.prekey
        pair.alice.wipe()
        assert identity.destroyed and prekey.destroyed
        with pytest.raises(RuntimeError):
            identity.sign(b"after the wipe")

    def test_an_smp_run_in_progress_is_destroyed(self, pair):
        pair.alice.smp_start(pair.bob_jid, SECRET)    # bob never answers
        session = pair.alice._engine.sessions[pair.bob_jid]
        vault = session.smp_vault
        assert vault is not None and vault.count() >= 1
        pair.alice.wipe()
        assert vault.count() == 0, "the SMP secret survived the wipe"
        assert session.rust_smp is None

    def test_a_half_finished_handshake_is_destroyed(self):
        """DAKE2 produced session keys; DAKE3 never arrived."""
        p = _pair()
        p.bob_wire.cut = True                        # bob's replies are lost
        p.alice.start_session(p.bob_jid)
        outputs = [s._dake_output for s in p.bob._engine.sessions.values()
                   if getattr(s, "_dake_output", None) is not None]
        outputs += [e._session_keys["_dake_output"]
                    for e in p.bob._engine.dake_engines.values()
                    if isinstance(getattr(e, "_session_keys", None), dict)
                    and e._session_keys.get("_dake_output") is not None]
        assert outputs, "no pending DAKE output to test against"
        p.bob.wipe()
        assert all(o.consumed for o in outputs), (
            "an unconsumed DakeOutput kept its session keys through the wipe")

    def test_the_engine_is_wiped_on_the_transports_loop_thread(self, recwarn):
        wire = LoopWire()
        p = _pair(alice_wire=wire)
        # The handshake runs on the loop thread, as inbound OTR does on a
        # device, so every DakeOutput is created there.
        wire.run_on_loop_thread(lambda: p.alice.start_session(p.bob_jid))
        wire.run_on_loop_thread(lambda: p.bob.wipe())
        wire.ran_on = None
        p.alice.wipe()
        assert wire.ran_on == wire.loop_ident, (
            "the engine was not wiped on the loop thread; an unsendable "
            "DakeOutput made there would leak instead of being zeroized")
        leaked = [w for w in recwarn.list if "unsendable" in str(w.message)]
        assert not leaked, "a DakeOutput was dropped on the wrong thread"


# ---------------------------------------------------------------------------
# Calls and transfers in flight
# ---------------------------------------------------------------------------

class TestCallsAndTransfersInFlight:

    def test_a_live_call_loses_its_keys_and_its_loop(self, verified,
                                                     audio_available):
        bridge = verified.alice.calls
        manager = bridge._ensure_manager()
        session = voice.VoiceCallSession(verified.bob_jid, bridge._loop,
                                         os.urandom(16), True)
        session.otr_material = (b"binding", "AA" * 64, "BB" * 64)
        session.state = voice.CallState.ACTIVE
        session.schedule.install_initial(b"\x11" * voice.ROOT_LEN)
        root = session.schedule.current_root()
        manager._calls[verified.bob_jid] = session
        loop, thread = bridge._loop, bridge._thread

        verified.alice.wipe()

        assert root.spent, "the call's epoch root survived the wipe"
        assert not manager._calls
        thread.join(timeout=5)
        assert not thread.is_alive() and loop.is_closed()

    def test_an_outgoing_transfer_loses_its_key(self, verified):
        path = os.path.join(tempfile.mkdtemp(), "note.txt")
        with open(path, "wb") as f:
            f.write(b"x" * 5000)
        assert verified.alice.send_file(verified.bob_jid, path) == FileOutcome.STARTED
        manager = verified.alice.files._manager
        senders = [t.sender for t in manager.outgoing.values()]
        assert senders
        verified.alice.wipe()
        assert all(s.zeroized for s in senders)

    def test_an_incoming_transfer_loses_its_key_and_partial_file(self, verified):
        path = os.path.join(tempfile.mkdtemp(), "note.txt")
        with open(path, "wb") as f:
            f.write(b"y" * 5000)
        verified.bob_wire.cut = True     # keep bob's accept from completing it
        verified.alice.send_file(verified.bob_jid, path)
        rows = verified.bob.transfers()
        assert rows, "the offer never reached bob"
        manager = verified.bob.files._manager
        verified.bob.accept_file(rows[0]["id"])
        incoming = list(manager.incoming.values())
        receivers = [t.receiver for t in incoming if t.receiver is not None]
        partials = [t.tmp_path for t in incoming if t.tmp_path]
        verified.bob.wipe()
        assert all(r.zeroized for r in receivers)
        assert not any(os.path.exists(p) for p in partials)


# ---------------------------------------------------------------------------
# Nothing comes back
# ---------------------------------------------------------------------------

class TestNothingComesBack:

    def test_a_late_frame_neither_reaches_the_ui_nor_makes_a_session(self, pair):
        pair.alice.wipe()
        before = len(pair.alice_sink.events)
        pair.bob.send_message(pair.alice_jid, "are you there?")
        assert pair.alice._engine.sessions == {}
        assert len(pair.alice_sink.events) == before

    def test_the_engine_refuses_every_entry_point(self, pair):
        pair.alice.wipe()
        engine = pair.alice._engine
        for call in (lambda: engine.get_or_create_session(pair.bob_jid),
                     lambda: engine.handle_outgoing_message(pair.bob_jid, "hi"),
                     lambda: engine.handle_incoming_message(pair.bob_jid, "?OTRv4 x"),
                     lambda: engine.start_smp(pair.bob_jid, SECRET)):
            with pytest.raises(otr.EnhancedSessionManager.EngineWiped):
                call()

    def test_the_facade_refuses_without_rebuilding_anything(self, pair):
        pair.alice.wipe()
        assert pair.alice.start_call(pair.bob_jid) == CallOutcome.UNAVAILABLE
        assert pair.alice.send_file(pair.bob_jid, "/nope") == FileOutcome.UNAVAILABLE
        assert pair.alice.transfers() == []
        assert pair.alice._calls_bridge is None
        assert pair.alice._files_bridge is None
        pair.alice.poll_calls()
        assert pair.alice._calls_bridge is None
        from android_bridge.app import BridgeError
        try:
            pair.alice.start_session(pair.bob_jid)   # refused one way or another
        except BridgeError:
            pass
        assert pair.alice._engine.sessions == {}

    def test_wiping_twice_is_harmless(self, pair):
        first = pair.alice.wipe()
        second = pair.alice.wipe()
        assert first["already_wiped"] is False and not first["errors"]
        assert second["already_wiped"] is True and not second["errors"]

    def test_wiping_with_nothing_running_is_harmless(self):
        app = OtrApp(_manager(), Wire(), Sink())
        report = app.wipe()
        assert not report["errors"]
        assert report["sessions"] == 0

    def test_the_transport_is_closed_not_merely_disconnected(self, pair):
        pair.alice.wipe()
        assert pair.alice_wire.closed
        assert pair.alice._transport is None


# ---------------------------------------------------------------------------
# Disk
# ---------------------------------------------------------------------------

class TestWhatWasOnDisk:

    def _plant(self, home):
        base = os.path.join(home, ".otrv4plus")
        for rel in ("keys/.device_seed", "files/photo.jpg",
                    "files/.incoming/part.tmp", "trust.json"):
            path = os.path.join(base, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "wb") as f:
                f.write(os.urandom(64))
        return base

    def test_the_python_state_tree_is_destroyed(self, pair, isolated_home):
        base = self._plant(isolated_home)
        report = pair.alice.wipe()
        assert not os.path.exists(base)
        assert report["files_destroyed"] == 4

    def test_a_symlink_cannot_turn_the_wipe_on_something_else(self, isolated_home):
        outside = tempfile.mkdtemp(prefix="outside-")
        precious = os.path.join(outside, "keep.txt")
        with open(precious, "w") as f:
            f.write("not ours")
        base = self._plant(isolated_home)
        os.symlink(precious, os.path.join(base, "files", "link"))
        OtrApp(_manager(), Wire(), Sink()).wipe()
        assert open(precious).read() == "not ours"

    def test_the_configured_file_directory_is_destroyed_too(self, monkeypatch):
        elsewhere = tempfile.mkdtemp(prefix="received-")
        monkeypatch.setenv("OTRV4PLUS_FILE_DIR", elsewhere)
        with open(os.path.join(elsewhere, "doc.pdf"), "wb") as f:
            f.write(b"%PDF")
        OtrApp(_manager(), Wire(), Sink()).wipe()
        assert not os.path.exists(elsewhere)

    def test_a_fresh_launch_afterwards_works_and_is_a_new_identity(self, pair):
        old_fp = pair.alice.local_fingerprint()
        pair.alice.wipe()
        again = _pair()
        again.alice.start_session(again.bob_jid)
        assert again.alice.security_state(again.bob_jid) is not SecurityState.PLAINTEXT
        assert again.alice.local_fingerprint() != old_fp
        again.alice.shutdown()
        again.bob.shutdown()


# ---------------------------------------------------------------------------
# The controller Kotlin drives
# ---------------------------------------------------------------------------

class TestTheControllerWipes:

    def _controller(self):
        from android_bridge.connection import ConnectionController, ConnectionProfile
        app = OtrApp(_manager(), None, None)
        profile = ConnectionProfile(jid="me@example.test", server="example.test")
        return ConnectionController(app, profile), app

    def test_a_wiped_controller_never_connects_again(self):
        ctl, app = self._controller()
        report = ctl.wipe()
        assert report["ok"]
        assert app.wiped
        assert ctl.connect("pw")["code"] == "wiped"
        assert ctl.register("pw")["code"] == "wiped"

    def test_wipe_during_a_connection_attempt_stops_it(self):
        ctl, app = self._controller()
        cancelled = threading.Event()

        class Slow:
            is_connected = False
            def cancel(self): cancelled.set()
            def close(self): pass

        ctl._transport = Slow()
        ctl.wipe()
        assert cancelled.is_set()
        assert ctl._transport is None


# ---------------------------------------------------------------------------
# The Android half, which this container cannot compile
# ---------------------------------------------------------------------------
#
# The ORDER and POLICY are in `security/WipeAndExit.kt`, a plain-Kotlin leaf
# that `WipeAndExitTest` executes on CI (and that compiles and runs outside
# Gradle, with the Kotlin compiler from the Gradle cache). What is checked
# here is the platform wiring around it, from the source.

_ANDROID = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "android", "app", "src", "main", "java", "org",
                        "otrv4plus", "android")


def _kt(*parts):
    with open(os.path.join(_ANDROID, *parts), encoding="utf-8") as f:
        return f.read()


def _body(source, signature):
    """The brace-delimited body following [signature]."""
    start = source.index(signature)
    open_at = source.index("{", start)
    depth = 0
    for i in range(open_at, len(source)):
        if source[i] == "{":
            depth += 1
        elif source[i] == "}":
            depth -= 1
            if depth == 0:
                return source[open_at:i + 1]
    raise AssertionError("unbalanced body for %s" % signature)


class TestTheAndroidSideIsWired:

    def test_the_service_runs_every_step_through_the_plan(self):
        body = _body(_kt("connection", "OtrConnectionService.kt"),
                     "private fun wipeAndExit()")
        plan = _kt("security", "WipeAndExit.kt")
        steps = _body(plan, "enum class Step")
        for step in [s.strip().rstrip(",") for s in steps.strip("{}").split("\n")
                     if s.strip()]:
            assert "WipeAndExit.Step.%s to" % step in body, (
                "the service supplies no action for %s" % step)
        assert "WipeAndExit.Runner(" in body

    def test_each_step_does_what_the_plan_says(self):
        body = _body(_kt("connection", "OtrConnectionService.kt"),
                     "private fun wipeAndExit()")
        for needle in ("core.wipe()", "KeystoreVault.destroy(context)",
                       "cancelAll()", "cacheDir", "killProcess",
                       "drainer?.cancel()", "worker?.cancel()"):
            assert needle in body, "the wipe does not do %s" % needle
        # Stopped, THEN killed, so a sticky service is not restarted.
        assert body.index("stopSelf()") < body.index("killProcess")

    def test_nothing_starts_once_a_wipe_has_begun(self):
        body = _body(_kt("connection", "OtrConnectionService.kt"),
                     "override fun onStartCommand(")
        guard = body.index("wipeStarted.get()")
        assert guard < body.index("ACTION_START ->"), (
            "a queued ACTION_START could run after the wipe began")

    def test_the_vault_key_is_deleted_before_the_files(self):
        body = _body(_kt("security", "KeystoreVault.kt"),
                     "fun destroy(context: Context)")
        assert body.index("deleteEntry(ALIAS)") < body.index("deleteRecursively")

    def test_the_core_wipes_even_a_cold_process_and_forgets_itself(self):
        body = _body(_kt("bridge", "ChaquopyOtrCore.kt"),
                     "override fun wipe()")
        assert 'callAttr("wipe")' in body
        assert '"android_bridge.wipe"' in body and '"wipe_disk"' in body
        for field in ("controller = null", "app = null", "initResult = null"):
            assert field in body

    def test_the_three_buttons_say_what_they_do(self):
        screen = _kt("ui", "ConnectScreen.kt")
        assert 'onClick = { model.disconnect() },\n                ) { Text("Disconnect") }' in screen
        assert 'onClick = { model.logout() },\n                ) { Text("Sign out") }' in screen
        assert "WipeAndExit.CONFIRM_BODY" in screen
        assert "model.wipeAndExit()" in screen
        assert "finishAndRemoveTask()" in screen

    def test_the_plan_names_the_python_roots_this_module_destroys(self):
        from android_bridge import wipe as disk
        plan = _kt("security", "WipeAndExit.kt")
        assert "~/.otrv4plus" in plan
        roots = disk.python_state_roots()
        assert roots[0].endswith(os.sep + ".otrv4plus")


# ---------------------------------------------------------------------------
# Answering one challenge does not persist the passphrase or pre-answer the next
# ---------------------------------------------------------------------------

class TestAnAndroidSmpAnswerIsNotRemembered:
    """`smp_respond` went through the terminal AUTO-RESPOND setter.

    That wrote the passphrase to `smp_secrets.json` (under a key derived from
    a seed file beside it), kept it in a Python dict for the life of the
    process, and re-bound it into every later session -- so the next SMP1 the
    peer sent was answered without the dialog ever appearing.
    """

    def test_nothing_is_stored_after_a_verification(self, verified):
        engine = verified.bob._engine
        assert engine.smp_storage._secrets == {}, "the passphrase is held in Python"
        assert not os.path.exists(engine.smp_storage.secrets_path), (
            "the passphrase was written to disk")

    def test_the_next_challenge_waits_for_the_user(self, verified):
        p = verified
        p.alice._engine.sessions.pop(p.bob_jid, None)
        p.bob._engine.sessions.pop(p.alice_jid, None)
        otr._dake1_rate_limiter._attempts.clear()
        p.alice.start_session(p.bob_jid)
        p.alice.smp_start(p.bob_jid, SECRET)
        assert p.bob.smp_secret_required(p.alice_jid), (
            "the second challenge was answered from a remembered passphrase")
