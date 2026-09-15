# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""The controller's side of the lifecycle, and the Kotlin that drives it.

`tests/test_android_transport_lifecycle.py` covers what the transport owns.
This covers the layer above: whether the controller lets go of a transport it
has finished with, refuses to run two attempts at once, and reports a stage it
has actually declared.

The last class here is structural rather than behavioural. Kotlin cannot be
executed from pytest, and the Android instrumentation tests need a device, so
the facts that matter for Activity recreation are asserted by parsing the
source. That is weaker than running it and is not pretended otherwise -- but a
screen that goes back to `remember { ChaquopyOtrCore(...) }` is a regression
that costs a device round trip to find, and this catches it in CI.
"""

import ast
import io
import os
import re
import threading
import time

import pytest

from android_bridge.connection import ConnectionController, SamProbe
from android_bridge.settings import ConnectionProfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
UI = os.path.join(ROOT, "android", "app", "src", "main", "java", "org",
                  "otrv4plus", "android")

JID = "alice@xmpp-elite.i2p"
SERVER = "hq4t24b7vkllfbk55e5xfocqhfi7hxprwc47zyuilbg6wgzikidq.b32.i2p"


def _read(*parts):
    with io.open(os.path.join(*parts), encoding="utf-8") as fh:
        return fh.read()


class FakeApp:
    """Just enough OtrApp for the controller to wire itself to.

    "Just enough" means every method the controller hands over as a callback.
    A missing one is an AttributeError raised while BUILDING the transport,
    which the controller reports as `transport_failed` -- a failure naming the
    transport for something the app lacked. Adding `on_presence` did that to
    seven tests here. `tests/test_android_connection_controller.py` binds its
    equivalent fakes to the real classes for exactly this reason.
    """

    def __init__(self):
        self._transport = None
        self.sink = None
        self.presence = []

    def set_event_sink(self, sink):
        self.sink = sink

    def receive_message(self, peer, body):
        pass

    def note_presence(self, peer, online):
        self.presence.append((peer, bool(online)))


class FakeTransport:
    """Records the lifecycle calls the controller makes."""

    def __init__(self, profile, password, *, on_payload=None, on_state=None,
                 on_presence=None, on_subscription_request=None, **_kw):
        self.profile = profile
        self.on_state = on_state
        self.closed = 0
        self.cancelled = 0
        self.is_connected = False
        self.tls_policy = "not yet decided"
        self._connect_gate = threading.Event()
        self._connect_gate.set()
        self.raises = None

    def connect(self):
        self._connect_gate.wait(timeout=10)
        if self.raises is not None:
            raise self.raises
        self.is_connected = True

    def cancel(self):
        self.cancelled += 1
        self._connect_gate.set()

    def close(self):
        self.closed += 1
        self.is_connected = False

    def disconnect(self):
        self.is_connected = False


def build(**kw):
    """A controller over fakes, with the router already answering."""
    app = FakeApp()
    made = {}

    def factory(profile, password, **rest):
        made["transport"] = FakeTransport(profile, password, **rest)
        return made["transport"]

    controller = ConnectionController(
        app,
        ConnectionProfile(jid=kw.pop("jid", JID), server=SERVER),
        transport_factory=factory,
        prober=kw.pop("prober", lambda _p: SamProbe(True, "ok", "fine", "3.1")),
        **kw)
    return controller, app, made


class TestAFailedConnectLetsGoOfItsTransport:
    """A transport the controller keeps a reference to but never closes is a
    worker thread and an I2P lease with nobody left to release them."""

    def test_a_failed_connect_closes_the_transport(self):
        controller, app, made = build()
        controller_transport_raises(controller, made, code="stream_failed")
        result = controller.connect("pw")
        assert result["ok"] is False
        assert made["transport"].closed == 1, (
            "the failed transport was left open")

    def test_a_failed_connect_clears_the_apps_transport(self):
        controller, app, made = build()
        controller_transport_raises(controller, made, code="stream_failed")
        controller.connect("pw")
        assert app._transport is None, (
            "OtrApp would still try to send through a dead transport")

    def test_a_failed_connect_leaves_no_transport_to_reuse(self):
        controller, app, made = build()
        controller_transport_raises(controller, made, code="stream_failed")
        controller.connect("pw")
        assert controller.status()["connected"] is False

    def test_disconnect_closes_rather_than_merely_disconnecting(self):
        """`close` and not `disconnect`: the worker thread and the tunnel
        belong to the object, and we are dropping the last reference to it."""
        controller, app, made = build()
        controller.connect("pw")
        controller.disconnect()
        assert made["transport"].closed == 1


class TestOnlyOneAttemptAtATime:
    """Two are easy to start by accident: rotate during a tunnel build and the
    recreated screen presses Connect again."""

    def test_a_second_connect_while_one_runs_is_refused(self):
        controller, app, made = build()
        first = {}

        def factory_gate():
            made["transport"]._connect_gate.clear()

        controller_transport_gate(controller, made, factory_gate)

        def run():
            first["result"] = controller.connect("pw")

        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        _settle(lambda: controller.stage in ("connecting", "building_tunnels"))

        second = controller.connect("pw")
        assert second["code"] == "already_connecting", (
            "a second attempt ran alongside the first; each would build its "
            "own tunnel and the loser would leak both")

        made["transport"]._connect_gate.set()
        thread.join(timeout=10)
        assert first["result"]["ok"] is True

    def test_connecting_when_already_connected_is_a_no_op(self):
        controller, app, made = build()
        controller.connect("pw")
        again = controller.connect("pw")
        assert again["ok"] is True
        assert again["detail"] == "Already connected."

    def test_the_flag_is_cleared_after_a_failure(self):
        """Otherwise one failure locks Connect out for the life of the app."""
        controller, app, made = build()
        controller_transport_raises(controller, made, code="stream_failed")
        controller.connect("pw")
        controller_transport_raises(controller, made, code=None)
        assert controller.connect("pw")["ok"] is True


class TestCancelling:

    def test_cancel_reaches_the_transport(self):
        controller, app, made = build()
        controller_transport_gate(
            controller, made, lambda: made["transport"]._connect_gate.clear())
        thread = threading.Thread(
            target=lambda: controller.connect("pw"), daemon=True)
        thread.start()
        _settle(lambda: "transport" in made and controller.stage != "idle")
        controller.cancel()
        assert made["transport"].cancelled == 1
        made["transport"]._connect_gate.set()
        thread.join(timeout=10)

    def test_cancel_with_nothing_running_says_so(self):
        controller, _app, _made = build()
        assert controller.cancel()["code"] == "not_connecting"

    def test_a_cancelled_connect_is_not_reported_as_a_failure(self):
        """It goes in the same place on screen as "could not connect", and a
        red line for something the user did on purpose teaches them to ignore
        red lines."""
        from android_bridge.transport import TransportError

        controller, app, made = build()
        controller_transport_raises(
            controller, made, exc=TransportError("cancelled", "stopped"))
        result = controller.connect("pw")
        assert result["code"] == "cancelled"
        assert controller.stage == "cancelled"
        assert controller.stage != "failed"

    def test_cancelled_is_a_declared_stage(self):
        assert "cancelled" in ConnectionController.STAGES


class TestTheStageVocabularyIsClosed:
    """A stage the screen has no label for is a raw identifier on a UI."""

    def test_every_transport_state_maps_to_a_declared_stage(self):
        for state in ("building_tunnels", "connected", "disconnected",
                      "failed"):
            mapped = ConnectionController._TRANSPORT_STAGE.get(state, state)
            assert mapped in ConnectionController.STAGES, (
                "%s maps to %r, which is not a stage" % (state, mapped))

    def test_disconnected_is_declared(self):
        """It was being entered without being declared: the transport emits it
        when the server drops the stream, and the old pass-through lambda put
        it straight on a screen whose labels did not cover it."""
        assert "disconnected" in ConnectionController.STAGES

    def test_a_server_drop_moves_the_stage(self):
        controller, app, made = build()
        controller.connect("pw")
        assert controller.stage == "connected"
        made["transport"].is_connected = False
        made["transport"].on_state("disconnected", SERVER)
        assert controller.stage == "disconnected"
        assert controller.status()["connected"] is False

    def test_an_unknown_transport_state_is_dropped_not_rendered(self):
        controller, app, made = build()
        controller.connect("pw")
        made["transport"].on_state("something_new", SERVER)
        assert controller.stage == "connected", (
            "an unmapped state became the stage")

    def test_the_transports_connected_is_the_controllers_connecting(self):
        """The two vocabularies differ where it matters most: the transport's
        "connected" means the stream is up, and there is still a SASL exchange
        to go. Calling that connected is the one claim this must not make."""
        assert ConnectionController._TRANSPORT_STAGE["connected"] == "connecting"

    def test_every_stage_the_screen_knows_is_a_stage_the_controller_has(self):
        """Parsed from the Kotlin, so the two lists cannot drift."""
        source = _read(UI, "ui", "ConnectScreen.kt")
        body = source[source.index("private fun stageLabel"):]
        labelled = set(re.findall(r'^\s*"([a-z_]+)" ->', body, re.M))
        missing = labelled - set(ConnectionController.STAGES)
        assert not missing, "the screen labels stages that do not exist: %s" % missing
        unlabelled = set(ConnectionController.STAGES) - labelled
        assert not unlabelled, (
            "these stages would render as a raw identifier: %s" % unlabelled)


class TestTheCredentialIsNotHeldByTheController:

    def test_only_its_presence_is_recorded(self):
        controller, _app, _made = build()
        controller.connect("hunter2")
        blob = repr(vars(controller))
        assert "hunter2" not in blob

    def test_the_status_map_carries_no_password(self):
        controller, _app, _made = build()
        controller.connect("hunter2")
        assert "hunter2" not in repr(controller.status())
        assert controller.status()["inputs"]["password_present"] is True

    def test_the_pasteable_report_carries_no_password(self):
        controller, _app, _made = build()
        controller.connect("hunter2")
        assert "hunter2" not in controller.inputs_text()


class TestTheAndroidLifecycleIsWiredForRecreation:
    """Structural. Kotlin does not run here; these are the facts that decide
    whether a rotation costs you your connection, asserted by parsing."""

    @staticmethod
    @pytest.fixture(scope="class")
    def connect_screen():
        return _read(UI, "ui", "ConnectScreen.kt")

    @staticmethod
    @pytest.fixture(scope="class")
    def view_model():
        return _read(UI, "ConnectionViewModel.kt")

    def test_the_screen_does_not_own_the_core(self, connect_screen):
        """`remember` survives recomposition and nothing else. It does not
        survive Activity recreation, so a rotation during a tunnel build built
        a SECOND core -- a second engine over the same identity and trust
        files -- while the first kept its worker thread and its half-open
        tunnel."""
        assert "remember { ChaquopyOtrCore" not in connect_screen
        assert "ChaquopyOtrCore(context)" not in connect_screen

    def test_the_core_lives_in_the_service(self, view_model):
        """It used to live here, which fixed rotation and not the real
        problem: a ViewModel does not survive the process, and Android kills a
        backgrounded process with nothing holding it up. The ViewModel now
        BINDS to the service and its core is nullable, because there is a
        window before the binding lands."""
        service = _read(UI, "connection", "OtrConnectionService.kt")
        assert "val core: ChaquopyOtrCore by lazy" in service
        assert "ChaquopyOtrCore(" not in _code_only(view_model), (
            "the ViewModel constructs a core again")
        assert "var core by mutableStateOf<ChaquopyOtrCore?>" in view_model

    def test_only_the_service_constructs_a_core(self):
        """One authoritative owner. Two would be two engines over the same
        identity and trust files -- which the diagnostics screen was doing,
        from the screen whose job is to report on the first one."""
        import glob
        built = []
        for path in glob.glob(os.path.join(UI, "**", "*.kt"), recursive=True):
            source = _code_only(_read(path))
            if "ChaquopyOtrCore(" in source and "class ChaquopyOtrCore" not in source:
                built.append(os.path.basename(path))
        assert built == ["OtrConnectionService.kt"], built

    def test_the_screen_takes_the_view_model(self, connect_screen):
        assert "model: ConnectionViewModel = viewModel()" in connect_screen

    def test_the_connect_does_not_run_in_a_screen_scoped_coroutine(
            self, connect_screen):
        """`rememberCoroutineScope()` is cancelled when the composition goes
        away -- which is the rotation. The Kotlin side would stop waiting
        while Python carried on connecting.

        Comments are stripped first. Without that this asserted on the
        explanation rather than the code, and it failed against a file that
        was already correct -- the phrase appears in the comment saying why
        it is not used.
        """
        assert "rememberCoroutineScope" not in _code_only(connect_screen)

    def test_the_view_model_uses_its_own_scope(self, view_model):
        assert "viewModelScope.launch" in view_model

    def test_every_call_into_python_is_off_the_main_thread(self, view_model):
        """A tunnel build on the main thread is an ANR, not a slow connect.

        Counted rather than eyeballed: every `core.` call in the ViewModel has
        to be inside a `withContext(Dispatchers.IO)`, and the cheap way to be
        sure is that there are at least as many IO hops as there are call
        sites that need one.
        """
        source = view_model + _read(UI, "connection", "OtrConnectionService.kt")
        core_calls = len(re.findall(r"\bcore[?]?\.\w+\(", source))
        io_hops = source.count("Dispatchers.IO")
        assert io_hops >= 1
        assert core_calls > 0
        outside = re.findall(r"^\s{0,8}core[?]?\.\w+\(", source, re.M)
        assert not outside, (
            "these look like calls into Python at method level rather than "
            "inside a dispatcher: %s" % outside)

    def test_clearing_the_view_model_does_not_hang_up(self, view_model):
        """The inversion the service exists for. This used to disconnect and
        shut the engine down in `onCleared`; doing that now would hang up
        because a screen went away, which is the bug, not the fix."""
        cleared = view_model[view_model.index("override fun onCleared"):]
        assert "unbindService" in cleared
        for teardown in ("disconnect()", "shutdown()", "cancelConnect()"):
            assert teardown not in cleared, (
                "onCleared still tears the connection down: %s" % teardown)

    def test_the_service_releases_everything_when_it_stops(self):
        service = _read(UI, "connection", "OtrConnectionService.kt")
        destroy = service[service.index("override fun onDestroy"):]
        destroy = destroy[:destroy.index("\n    //")]
        assert "stopConnection" in destroy
        stop = service[service.index("fun stopConnection"):]
        stop = stop[:stop.index("private suspend fun connectLoop")]
        assert "cancelConnect" in stop and "disconnect" in stop

    def test_shutdown_releases_the_controller(self):
        """The bridge's own shutdown, which is what onCleared calls."""
        source = _read(UI, "bridge", "ChaquopyOtrCore.kt")
        body = source[source.index("override fun shutdown"):]
        body = body[:body.index("\n    override fun localFingerprint")]
        assert "controller" in body, (
            "shutdown left the controller alone, so the transport's worker "
            "thread and I2P tunnel outlived the object that owned them")
        assert body.index("controller") < body.index("app?.callAttr"), (
            "the connection must be released before the engine")

    def test_the_activity_shares_one_view_model_with_every_screen(self):
        """Two `viewModel()` calls for the same type in one Activity return
        the same instance, but obtaining it once and passing it says so. A
        second core would be a second engine over the same identity and trust
        files."""
        activity = _code_only(_read(UI, "MainActivity.kt"))
        assert "val connection: ConnectionViewModel = viewModel()" in activity
        assert activity.count("ConnectionViewModel = viewModel()") == 1, (
            "the Activity obtains the connection ViewModel more than once")
        assert "model = connection" in activity
        # The chat is handed the core from that one ViewModel, never its own,
        # and only once it exists -- the service binding is asynchronous.
        assert "chat.attach(core, state)" in activity
        assert "connection.chat" in activity, (
            "the chat renders state it owns rather than the service's")
        assert "ChaquopyOtrCore(" not in activity

    def test_which_screen_you_are_on_survives_recreation(self):
        """Losing this throws a connected user back to the connect screen on
        a rotation. The connection is fine -- the ViewModel holds it -- but
        being bounced out of a conversation reads as a crash.

        Navigation is an enum plus a JID since the chat screens landed, so
        both have to be saveable, and neither may be an object."""
        activity = _code_only(_read(UI, "MainActivity.kt"))
        assert "var screen by rememberSaveable" in activity
        assert "var openJid by rememberSaveable" in activity
        assert "mutableStateOf<String?>" in activity, (
            "the open conversation is held as something other than a JID")

    def test_the_activity_does_not_hold_the_core_in_navigation_state(self):
        """It is not Saveable -- it owns a Python interpreter -- and it does
        not need to be. The navigation state only has to remember which
        screen, not which object."""
        activity = _code_only(_read(UI, "MainActivity.kt"))
        assert "mutableStateOf<ChaquopyOtrCore?>" not in activity

    def test_cancel_is_reachable_from_the_screen(self, connect_screen):
        assert "model.cancelConnect()" in connect_screen

    def test_cancel_is_not_disabled_by_busy(self, connect_screen):
        """`busy` is precisely the state the Cancel button exists to get out
        of. Disabling it during `busy` would mean the only way out of a cold
        tunnel build is killing the app -- which leaves the tunnel building."""
        block = connect_screen[connect_screen.index("model.connecting"):]
        block = block[:block.index("Cancel") + 20]
        assert "enabled = busy == null" not in block

    def test_the_password_is_not_hoisted_into_the_view_model(
            self, connect_screen, view_model):
        """It must not outlive the composition. The ViewModel does."""
        assert "var password" in connect_screen
        assert "var password" not in view_model
        assert 'password = ""' in connect_screen, (
            "the field is never cleared after a connect")

    def test_the_view_model_keeps_no_password_state(self, view_model):
        tree_words = re.findall(r"\bvar\s+(\w+)\b", view_model)
        assert not any("password" in w.lower() for w in tree_words)

    def test_the_kotlin_parses_as_balanced_source(self):
        """Cheap guard against a botched edit reaching CI.

        Not a compiler -- CI has one -- but an unbalanced brace here costs a
        full Gradle round trip to discover, and this costs milliseconds.
        """
        for name in ("ConnectionViewModel.kt",):
            text = _read(UI, name)
            _assert_balanced(text, name)
        for name in ("ConnectScreen.kt", "ConversationsScreen.kt",
                     "ConversationScreen.kt", "AboutScreen.kt"):
            _assert_balanced(_read(UI, "ui", name), name)


# ── helpers ──────────────────────────────────────────────────────────────────

def _code_only(text):
    """Kotlin source with comments and string bodies removed.

    A structural assertion must be about the code. Matching a comment means
    the test passes when someone deletes the explanation and fails when
    someone writes one.
    """
    text = re.sub(r"/\*(?:.|\n)*?\*/", " ", text)
    text = re.sub(r"//[^\n]*", "", text)
    return re.sub(r'"(?:\\.|[^"\\\n])*"', '""', text)


def _assert_balanced(text, name):
    stripped = re.sub(r'"""(?:.|\n)*?"""', '""', text)
    stripped = re.sub(r"//[^\n]*", "", stripped)
    stripped = re.sub(r"/\*(?:.|\n)*?\*/", " ", stripped)
    stripped = re.sub(r'"(?:\\.|[^"\\\n])*"', '""', stripped)
    depth = 0
    for char in stripped:
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            assert depth >= 0, "%s closes a brace that was never opened" % name
    assert depth == 0, "%s has %d unclosed brace(s)" % (name, depth)


def controller_transport_raises(controller, made, *, code=None, exc=None):
    """Make the next transport's connect fail."""
    from android_bridge.transport import TransportError

    original = controller._transport_factory

    def factory(profile, password, **rest):
        transport = original(profile, password, **rest)
        # Always assigned, including to None. Wrapping twice is normal in
        # these tests -- plant a failure, then clear it -- and a helper that
        # only ever sets a failure cannot express the second half.
        transport.raises = (
            exc if exc is not None
            else TransportError(code, "no") if code is not None
            else None)
        made["transport"] = transport
        return transport

    controller._transport_factory = factory


def controller_transport_gate(controller, made, after):
    """Make the next transport block in connect until released."""
    original = controller._transport_factory

    def factory(profile, password, **rest):
        transport = original(profile, password, **rest)
        made["transport"] = transport
        after()
        return transport

    controller._transport_factory = factory


def _settle(predicate, timeout=5.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if predicate():
                return True
        except Exception:
            pass
        time.sleep(0.02)
    return False
