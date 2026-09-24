#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Android could not place a call, and displayed the peer's call signalling.

WHAT EXISTED AND WHAT DID NOT
=============================
All of the call machinery existed: `otrv4plus_voice.VoiceCallManager` with
its validated state machine, signalling, key schedule and SMP gate, and
`otrv4plus_audio`'s AAudio backend -- both already packaged into the APK,
with `minSdk` at API 26 for AAudio.

What did not exist was any way for Android to reach them.
`android_bridge.app` had `note_call_state` and `call_state` -- two mirrors
of a state nothing could enter -- and no `start_call`, `answer_call` or
`end_call`.

AND THE INBOUND HALF WAS A DEFECT, not merely a gap. The terminal client
tests `CALL_PREFIX` on its decrypted bodies in three places; this facade
tested it nowhere. Measured through two real bridges with a live OTR
session, with the peer sending one control message:

    receive_message returned: '?OTRv4-CALL:INVITE:aa|bb|cc|dd'

That string went to the UI as a chat message from the user's contact.

WHAT IS REAL IN THESE TESTS
===========================
The `VoiceCallManager` is the real one. The state machine, the transition
table, the signalling parser, the rate limiter and -- the one that matters
-- the SMP gate are all the shipped implementation, driven through the
bridge the handset calls.

One thing is injected, through the module's own `bind_host` API and nothing
else: `voice_available`. That hook is how `otrv4plus_voice` asks its host
whether this platform has opus and an audio backend, and this host has
neither -- there is no libaaudio.so and no audio device in a container. It
is the platform answer, not call logic, and `bind_host` exists precisely so
the host supplies it.

WHAT THESE TESTS CANNOT REACH
=============================
Anything past `create_session()`: real SAM, real I2P tunnels, real AAudio
capture and playback. Those need a handset and a router, are recorded as
such in `tests/test_android_audio_path.py`, and are NOT faked here. A call
in these tests gets as far as the state machine can take it without a
network, and the assertions stop exactly there.
"""

import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

otr = pytest.importorskip("otrv4_")
pytest.importorskip("otrv4_core")
voice = pytest.importorskip("otrv4plus_voice")

from android_bridge.app import OtrApp, Transport                  # noqa: E402
from android_bridge.events import (CallState, CallStateChanged,   # noqa: E402
                                   SecurityState, SmpState)
from android_bridge.voice import CallBridge, CallOutcome, is_call_signal  # noqa: E402

SECRET = "a shared secret we both know"


class Sink:
    """Collects the events the UI would have received."""

    def __init__(self):
        self.events = []

    def on_event(self, event):
        self.events.append(event)

    def call_states(self):
        return [e.state for e in self.events
                if isinstance(e, CallStateChanged)]

    def codes(self):
        return [getattr(e, "code", None) for e in self.events]


class Wire(Transport):
    """Delivers whatever one bridge sends straight into the other."""

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


class Pair:
    def __init__(self, alice, bob, alice_jid, bob_jid, alice_sink, bob_sink):
        self.alice, self.bob = alice, bob
        self.alice_jid, self.bob_jid = alice_jid, bob_jid
        self.alice_sink, self.bob_sink = alice_sink, bob_sink


@pytest.fixture
def audio_available(monkeypatch):
    """Tell the ANDROID host this device has audio.

    THE PLATFORM ANSWER, NOT CALL LOGIC. On Android the voice host hooks are
    `android_bridge.android_audio`'s -- the APK's Rust Opus codec and AAudio
    -- bound by `CallBridge` after `otrv4plus_xmpp` has bound the Termux ones.
    A container has no libaaudio.so, so the one thing supplied here is
    `aaudio_available`. The codec is the real Rust one when this core was
    built with `android-opus` (CI builds it so); a stand-in only otherwise.
    Every gate that decides whether a call may happen, including the SMP one,
    remains the shipped implementation.

    It used to override `_HOST["voice_available"]` -- the TERMUX hook. The
    Android bridge no longer asks that hook, which is the fix for
    "opuslib not installed" on a handset.
    """
    import types
    import otrv4plus_xmpp                                    # noqa: F401
    from android_bridge import android_audio
    monkeypatch.setattr(android_audio, "aaudio_available", lambda: True)
    if android_audio.codec() is None:
        fake = types.SimpleNamespace(
            Encoder=object, Decoder=object, APPLICATION_VOIP=2048,
            SIGNAL_VOICE=3001, BANDWIDTH_WIDEBAND=1103)
        monkeypatch.setattr(android_audio, "codec", lambda: fake)
    yield


@pytest.fixture
def voice_log():
    """Capture what the call manager says, through its own `print` hook.

    Needed because the gate is not the only thing that can refuse an INVITE,
    and a test that merely asserts "no call happened" cannot tell which
    refusal it got. `_on_invite` rejects an unverified peer with one line and
    a bad destination with another; this reads the difference.

    `_HOST["print"]` is the module's own output hook -- the same one
    `otrv4plus_xmpp` binds to the terminal's `print`. Nothing about the call
    logic is replaced.
    """
    lines = []
    previous = voice._HOST["print"]
    voice.bind_host(print=lambda *a, **k: lines.append(
        " ".join(str(x) for x in a)))
    yield lines
    voice._HOST["print"] = previous


@pytest.fixture
def pair(audio_available):
    """Two Android bridges with a real encrypted session between them."""
    import uuid
    alice_jid = "alice-%s@example.test" % uuid.uuid4().hex[:8]
    bob_jid = "bob-%s@example.test" % uuid.uuid4().hex[:8]
    otr._dake1_rate_limiter._attempts.clear()

    alice_wire, bob_wire = Wire(), Wire()
    alice_sink, bob_sink = Sink(), Sink()
    alice = OtrApp(_manager(), alice_wire, alice_sink)
    bob = OtrApp(_manager(), bob_wire, bob_sink)
    alice_wire.peer_app, alice_wire.peer_id = bob, alice_jid
    bob_wire.peer_app, bob_wire.peer_id = alice, bob_jid

    alice.start_session(bob_jid)
    assert alice.security_state(bob_jid) is not SecurityState.PLAINTEXT, \
        "the fixture never reached an encrypted session"

    made = Pair(alice, bob, alice_jid, bob_jid, alice_sink, bob_sink)
    try:
        yield made
    finally:
        for app in (alice, bob):
            try:
                app.shutdown()
            except Exception:
                pass


@pytest.fixture
def verified(pair):
    """The same two, having actually completed SMP.

    A real run through the Rust core, not a flag set on a session: the whole
    point of the gate below is that it reads cryptographic verification.
    """
    pair.alice.smp_start(pair.bob_jid, SECRET)
    pair.bob.smp_respond(pair.alice_jid, SECRET)
    assert pair.alice.smp_state(pair.bob_jid) is SmpState.VERIFIED, \
        "the fixture did not complete SMP"
    assert pair.bob.smp_state(pair.alice_jid) is SmpState.VERIFIED
    return pair


# -- the inbound defect ------------------------------------------------------


class TestCallSignallingIsNotAMessage:
    """The measured defect. A peer's control message was rendered as chat."""

    @staticmethod
    def _signal(sender, to, body):
        """One real control message, encrypted by the sender's own engine."""
        frame, _ = sender._engine.handle_outgoing_message(to, body)
        return (frame.decode("utf-8", errors="replace")
                if isinstance(frame, (bytes, bytearray)) else str(frame))

    def test_an_invite_is_not_returned_as_a_body(self, pair):
        text = self._signal(pair.bob, pair.alice_jid,
                            voice.CALL_PREFIX + "INVITE:aa|bb|cc|dd")
        assert pair.alice.receive_message(pair.bob_jid, text) is None, (
            "call signalling was handed to the UI as a chat message")

    def test_no_message_event_is_emitted_for_it(self, pair):
        from android_bridge.events import MessageReceived
        text = self._signal(pair.bob, pair.alice_jid,
                            voice.CALL_PREFIX + "END:aa")
        pair.alice.receive_message(pair.bob_jid, text)
        assert not [e for e in pair.alice_sink.events
                    if isinstance(e, MessageReceived)], (
            "a control message reached the conversation as an event")

    def test_an_ordinary_message_still_arrives(self, pair):
        """The branch must not swallow anything else."""
        text = self._signal(pair.bob, pair.alice_jid, "hello there")
        assert pair.alice.receive_message(pair.bob_jid, text) == "hello there"

    def test_a_body_merely_mentioning_the_prefix_is_still_a_message(self, pair):
        """Only a body that STARTS with it is signalling. Somebody quoting
        the prefix mid-sentence is talking."""
        said = "the prefix is " + voice.CALL_PREFIX + " apparently"
        text = self._signal(pair.bob, pair.alice_jid, said)
        assert pair.alice.receive_message(pair.bob_jid, text) == said

    def test_the_prefix_is_not_a_second_definition(self):
        """`is_call_signal` carries a fallback for the window before
        `otrv4plus_voice` is imported. It must equal the real one, or the two
        sides would disagree about what a call signal looks like."""
        from android_bridge import voice as bridge_voice
        assert bridge_voice.CALL_PREFIX_FALLBACK == voice.CALL_PREFIX

    def test_signalling_is_recognised_before_the_voice_module_loads(self):
        assert is_call_signal(voice.CALL_PREFIX + "INVITE:x")
        assert not is_call_signal("hello")
        assert not is_call_signal(None)
        assert not is_call_signal(b"?OTRv4-CALL:INVITE")


# -- the gate ----------------------------------------------------------------


class TestTheSmpGate:
    """The one rule this subsystem exists to enforce, driven both ways."""

    def test_an_unverified_peer_cannot_be_called(self, pair):
        """`start_call` returns False for an unverified peer, and the bridge
        turns that into an error event rather than a call."""
        pair.alice.start_call(pair.bob_jid)
        _settle(pair.alice)
        assert pair.alice.call_state(pair.bob_jid) is CallState.IDLE, (
            "a call was placed to a peer whose identity is not verified")
        assert "call_not_placed" in pair.alice_sink.codes()
        assert not _cleared_the_gate(pair.alice, pair.bob_jid), (
            "an unverified peer got past the verification gate")

    def test_an_unverified_peer_cannot_make_us_ring(self, pair, voice_log):
        """The inbound half, and the more important one: an INVITE from an
        unverified peer must not ring this device.

        ASSERTED ON THE REASON, not merely on "no call happened". An earlier
        version of this test checked only that the state stayed IDLE, and it
        passed with the SMP gate deleted -- because the INVITE was rejected a
        few lines later for a malformed destination instead. Two refusals,
        one indistinguishable from the other, and the test could not tell
        which one it had got.
        """
        _invite(pair.bob, pair.alice, pair.alice_jid, pair.bob_jid)
        _settle(pair.alice)
        assert pair.alice.call_state(pair.bob_jid) is CallState.IDLE, (
            "an unverified peer made the device ring")
        assert any("not SMP-verified" in line for line in voice_log), (
            "the INVITE was refused, but not by the verification gate: %r"
            % voice_log[-4:])

    def test_a_verified_peer_is_not_refused_by_the_gate(self, verified,
                                                        voice_log):
        """The other direction. Without it, the assertion above would still
        pass with the gate wired permanently shut."""
        _invite(verified.bob, verified.alice, verified.alice_jid,
                verified.bob_jid)
        _settle(verified.alice)
        assert not any("not SMP-verified" in line for line in voice_log), (
            "a verified peer's INVITE was refused as unverified")

    def test_a_verified_peer_gets_past_the_gate(self, verified):
        """The other direction of the same rule. Without this, a test suite
        that only ever asserts refusal would pass with the gate wired shut.

        It does NOT assert the call connects -- that needs SAM and a router.
        It asserts the gate was not what stopped it.
        """
        verified.alice.start_call(verified.bob_jid)
        _settle(verified.alice, tries=40)
        assert _cleared_the_gate(verified.alice, verified.bob_jid), (
            "a verified peer was refused by the verification gate")

    def test_verification_is_read_from_the_engine(self, verified):
        """Not from a flag this bridge could set. The manager's predicate is
        asked of the engine, so a bridge-side boolean cannot open the gate."""
        manager = verified.alice.calls._ensure_manager()
        assert manager is not None
        assert manager._smp_verified(verified.bob_jid) is True
        assert manager._smp_verified("stranger@example.test") is False


# -- the lifecycle -----------------------------------------------------------


class TestTheCallLifecycle:

    def test_nothing_to_answer_says_so(self, pair):
        assert pair.alice.answer_call(pair.bob_jid) == CallOutcome.NO_CALL

    def test_nothing_to_end_says_so(self, pair):
        assert pair.alice.end_call(pair.bob_jid) == CallOutcome.NO_CALL

    def test_ending_twice_is_not_an_error_the_second_time(self, pair):
        assert pair.alice.end_call(pair.bob_jid) == CallOutcome.NO_CALL
        assert pair.alice.end_call(pair.bob_jid) == CallOutcome.NO_CALL

    def test_a_call_needs_a_transport(self, pair):
        """Signalling rides the OTR channel over XMPP. Without a transport
        the INVITE cannot leave, and a call that silently never rings is
        worse than a refusal that says why."""
        pair.alice._transport = None
        assert pair.alice.start_call(pair.bob_jid) == CallOutcome.NOT_CONNECTED

    def test_state_is_idle_for_a_peer_with_no_call(self, pair):
        assert pair.alice.call_state(pair.bob_jid) is CallState.IDLE
        assert pair.alice.call_state("nobody@example.test") is CallState.IDLE

    def test_duration_is_zero_until_a_call_is_active(self, verified):
        """A timer must not start during a tunnel build: dialling is not
        talking, and a call that has not connected has lasted no time."""
        verified.alice.start_call(verified.bob_jid)
        _settle(verified.alice, tries=20)
        assert verified.alice.call_duration_seconds(verified.bob_jid) == 0

    def test_asking_for_state_does_not_build_a_call_manager(self, pair):
        """The conversation list polls this for every row. A device that has
        never placed a call must not load the voice stack to be told there is
        no call."""
        assert pair.alice._calls_bridge is None
        pair.alice.call_state(pair.bob_jid)
        assert pair.alice._calls_bridge is None, (
            "reading call state built a call bridge")


class TestVoiceAvailability:

    def test_an_unavailable_device_refuses_immediately(self, pair,
                                                       monkeypatch):
        """Synchronously, because it is a permanent fact about the device
        rather than something to discover two frames later. The answer is
        the ANDROID one (no AAudio), bound into the hook `start_call` asks."""
        from android_bridge import android_audio
        monkeypatch.setattr(android_audio, "aaudio_available", lambda: False)
        assert pair.alice.start_call(pair.bob_jid) == CallOutcome.UNAVAILABLE

    def test_the_reason_is_androids_and_is_the_one_start_call_asks(self, pair,
                                                                   monkeypatch):
        """Was `test_the_reason_comes_from_the_engines_own_hook`, which bound
        the Termux hook and asserted Android repeated it -- the very route by
        which "opuslib not installed" reached a handset. Now: the reason is
        android_audio's, and after a manager exists it is ALSO what
        `otrv4plus_voice._HOST["voice_available"]` answers, so the screen and
        `start_call` cannot disagree."""
        from android_bridge import android_audio
        monkeypatch.setattr(android_audio, "aaudio_available", lambda: False)
        assert pair.alice.voice_unavailable_reason() == android_audio.NO_AAUDIO
        pair.alice.calls._ensure_manager()
        assert voice._HOST["voice_available"]() == (False, android_audio.NO_AAUDIO)
        monkeypatch.setattr(android_audio, "codec", lambda: None)
        assert pair.alice.voice_unavailable_reason() == android_audio.NO_CODEC

    def test_an_available_device_reports_no_reason(self, pair):
        assert pair.alice.voice_unavailable_reason() == ""


# -- teardown ----------------------------------------------------------------


class TestTeardown:

    def test_shutdown_without_a_call_is_harmless(self, pair):
        pair.alice.shutdown()
        pair.alice.shutdown()

    def test_shutdown_releases_the_call_loop(self, verified):
        verified.alice.start_call(verified.bob_jid)
        _settle(verified.alice, tries=10)
        bridge = verified.alice._calls_bridge
        assert bridge is not None and bridge._thread is not None
        thread = bridge._thread

        verified.alice.shutdown()
        thread.join(timeout=5)
        assert not thread.is_alive(), (
            "the call loop thread outlived the sign-out that ended it")

    def test_shutdown_drops_the_bridge(self, verified):
        verified.alice.start_call(verified.bob_jid)
        _settle(verified.alice, tries=10)
        verified.alice.shutdown()
        assert verified.alice._calls_bridge is None

    def test_a_call_in_flight_is_cancelled_rather_than_abandoned(self,
                                                                 verified):
        """A `start_call` part way through a tunnel build is not in the
        manager's `_calls` yet, so ending the calls does not reach it.
        Stopping the loop underneath it would leave a pending task and an
        unawaited coroutine."""
        verified.alice.start_call(verified.bob_jid)
        bridge = verified.alice._calls_bridge
        assert bridge is not None
        verified.alice.shutdown()
        assert bridge._pending == set()

    def test_the_calls_go_before_the_sessions(self):
        """Ordering, from the source. A live call holds a SAM session and an
        I2P lease, and its END rides the OTR session being destroyed -- so
        ending calls after sessions means the peer is never told."""
        import inspect
        body = inspect.getsource(OtrApp.shutdown)
        assert body.index("_calls_bridge") < body.index("clear_all_sessions")


# -- the module boundary -----------------------------------------------------


class TestTheVoiceStackIsNotLoadedAtImport:
    """`tests/test_android_transport.py` bans `otrv4plus_xmpp` at module
    scope in the bridge -- "importing it drags in the engine, argparse,
    getpass and a terminal" -- and names the remedy: "the import has to move
    back inside a function". `android_bridge.voice` is imported at module
    scope by `android_bridge.app`, so the same rule has to hold for it."""

    @staticmethod
    def _module_scope_imports(module):
        import ast
        import inspect
        tree = ast.parse(inspect.getsource(module))
        names = []
        for node in tree.body:
            if isinstance(node, ast.Import):
                names += [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                names.append(node.module or "")
        return names

    def test_it_does_not_import_the_voice_stack_at_module_scope(self):
        import android_bridge.voice as mod
        top = self._module_scope_imports(mod)
        for banned in ("otrv4plus_xmpp", "otrv4plus_voice", "otrv4plus_audio",
                       "otrv4_", "slixmpp"):
            assert not any(n.startswith(banned) for n in top), (
                "%r is imported at module scope: %r" % (banned, top))

    def test_the_app_can_be_imported_without_the_voice_stack(self):
        """The property those bans protect, asserted directly: importing the
        facade must not drag the terminal client in with it."""
        import subprocess
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        code = ("import sys; sys.path.insert(0, %r);\n"
                "import android_bridge.voice, android_bridge.events\n"
                "print('xmpp' if 'otrv4plus_xmpp' in sys.modules else 'clean')"
                % root)
        out = subprocess.run([sys.executable, "-c", code],
                             capture_output=True, text=True, timeout=120)
        assert out.stdout.strip() == "clean", (
            "importing android_bridge.voice pulled in the terminal client: %s"
            % (out.stdout + out.stderr)[:400])


# -- helpers -----------------------------------------------------------------


def _settle(app, tries=20):
    """Let the call loop run. The bridge submits and returns, on purpose."""
    import time
    for _ in range(tries):
        time.sleep(0.05)
        app.poll_calls()


def _invite(sender, receiver, receiver_jid, sender_jid):
    """One real INVITE, encrypted by the sender's engine and delivered."""
    body = voice.CALL_PREFIX + "INVITE:%s|%s|%s|%s" % (
        "aa" * 16, "dest", "bb" * 56, "cc" * 1568)
    frame, _ = sender._engine.handle_outgoing_message(receiver_jid, body)
    text = (frame.decode("utf-8", errors="replace")
            if isinstance(frame, (bytes, bytearray)) else str(frame))
    receiver.receive_message(sender_jid, text)


def _cleared_the_gate(app, peer):
    """Whether `start_call` got PAST the verification gate for *peer*.

    `_last_invite[peer]` is written by `start_call` on the line immediately
    after the SMP check and the rate limit, and nowhere else:

        if not self._smp_verified(peer):
            self._explain_unverified(peer); return False
        ...
        self._last_invite[peer] = now

    So its presence is a precise, deterministic marker of "the gate let this
    through", and its absence of "it did not".

    A COARSER TEST WOULD PASS FOR THE WRONG REASON. Asserting merely that no
    error was reported does not work: past the gate, `start_call` goes on to
    build a SAM session, which cannot succeed in a container -- "could not
    create SAM session: [Errno 111] Connection refused" -- and reports the
    same failure code a refused call does. Gate and network are different
    things and this tells them apart.
    """
    manager = app.calls._ensure_manager()
    if manager is None:
        return False
    return peer in getattr(manager, "_last_invite", {})


# -- the Kotlin side ---------------------------------------------------------


ANDROID = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "android", "app", "src", "main", "java", "org", "otrv4plus", "android")
ANDROID_TESTS = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "android", "app", "src", "test", "java", "org", "otrv4plus", "android")


def _kt(*parts):
    import io
    with io.open(os.path.join(ANDROID, *parts), encoding="utf-8") as handle:
        return handle.read()


class TestTheTwoSidesAgreeOnTheCodes:
    """Kotlin branches on these strings. If the two lists drifted, a screen
    would be matching on an outcome Python never sends -- and the `else`
    branch, which says "the call could not be started", would be the only one
    a user ever saw."""

    @staticmethod
    def _python_codes():
        from android_bridge.voice import CallOutcome as C
        return {C.STARTED, C.NO_CALL, C.ALREADY, C.UNAVAILABLE,
                C.NOT_CONNECTED}

    @staticmethod
    def _kotlin_codes():
        import re
        source = _kt("bridge", "OtrCore.kt")
        block = source[source.index("object CallOutcome {"):]
        block = block[:block.index("\n}")]
        return set(re.findall(r'=\s*"([a-z_]+)"', block))

    def test_every_python_code_exists_in_kotlin(self):
        assert self._python_codes() <= self._kotlin_codes(), (
            "Python can answer with a code Kotlin does not know: %r"
            % (self._python_codes() - self._kotlin_codes()))

    def test_kotlin_invents_no_code_of_its_own(self):
        assert self._kotlin_codes() <= self._python_codes(), (
            "Kotlin branches on a code Python never sends: %r"
            % (self._kotlin_codes() - self._python_codes()))

    def test_the_call_state_names_match(self):
        """`CallState` crosses the boundary by NAME. A name on one side and
        not the other becomes IDLE on arrival -- a live call rendering as no
        call at all."""
        import re
        source = _kt("bridge", "OtrCore.kt")
        block = source[source.index("enum class CallState {"):]
        block = block[:block.index("companion object")]
        kotlin = set(re.findall(r"\b([A-Z][A-Z_]+)\b", block))
        python = {state.name for state in CallState}
        assert python <= kotlin, (
            "Python reports states Kotlin cannot name: %r" % (python - kotlin))


class TestTheCoreExposesTheCalls:
    """The methods that did not exist. Compose cannot run here, so the wiring
    is asserted structurally; the behaviour it reaches is driven above."""

    @staticmethod
    @pytest.fixture(scope="class")
    def core():
        return _kt("bridge", "ChaquopyOtrCore.kt")

    @pytest.mark.parametrize("method,attr", [
        ("fun startCall(", "start_call"),
        ("fun answerCall(", "answer_call"),
        ("fun endCall(", "end_call"),
        ("fun callState(", "call_state"),
        ("fun callDurationSeconds(", "call_duration_seconds"),
        ("fun voiceUnavailableReason(", "voice_unavailable_reason"),
    ])
    def test_each_call_method_exists_and_reaches_python(self, core, method,
                                                        attr):
        assert method in core, "%s is missing" % method
        body = core[core.index(method):]
        body = body[:body.index("\n\n")]
        assert '"%s"' % attr in body, (
            "%s does not call %r" % (method, attr))

    @pytest.mark.parametrize("attr", [
        "start_call", "answer_call", "end_call", "call_state",
        "call_duration_seconds", "voice_unavailable_reason"])
    def test_python_actually_has_that_method(self, attr):
        """The other half. A `callAttr` naming a method that does not exist
        is an AttributeError at the moment the user presses the button."""
        assert callable(getattr(OtrApp, attr, None)), (
            "ChaquopyOtrCore calls OtrApp.%s, which does not exist" % attr)

    def test_the_core_decides_nothing_about_verification(self, core):
        """The gate is `VoiceCallManager`'s. A second check here would be a
        second answer that could disagree with the one that actually
        refuses."""
        body = core[core.index("fun startCall("):]
        body = body[:body.index("fun answerCall(")]
        for decided in ("SMP_VERIFIED", "smpState", "securityState"):
            assert decided not in body, (
                "startCall decides on %s itself instead of letting the call "
                "manager refuse" % decided)


class TestTheCallUiRulesAreExecutable:
    """Same pattern as `RowSecurity`: the part that can be wrong is a
    dependency-free leaf, because this container cannot build Compose and a
    rule nothing runs is a rule nobody checked."""

    @pytest.mark.parametrize("name", ["CallUi.kt", "MicPermission.kt"])
    def test_the_rules_touch_neither_compose_nor_android(self, name):
        source = _kt("crypto", name)
        for line in source.splitlines():
            if line.startswith("import "):
                assert line.startswith("import org.otrv4plus."), (
                    "%s imports a platform type (%s), so its rules can no "
                    "longer be executed off a device" % (name, line.strip()))
        assert "@Composable" not in source

    @pytest.mark.parametrize("name", ["CallUiTest.kt", "MicPermissionTest.kt"])
    def test_a_kotlin_test_drives_them(self, name):
        assert os.path.exists(os.path.join(ANDROID_TESTS, "crypto", name))

    def test_only_a_verified_conversation_is_offered_a_call(self):
        """The affordance rule, read from the source. Driven in `CallUiTest`;
        asserted here too because it is the one that must not be relaxed by
        somebody who cannot run the Kotlin tests."""
        source = _kt("crypto", "CallUi.kt")
        block = source[source.index("fun offer("):]
        block = block[:block.index("enum class Direction")]
        available = block[:block.index("Offer.Available") + 20]
        assert "SecurityState.SMP_VERIFIED" in available, (
            "something other than a verified identity is offered a call")
        assert block.count("Offer.Available") == 1, (
            "more than one security state is offered a call")


class TestCallStateReachesTheUi:
    """The manager publishes no state callback -- it moves a session through
    a validated transition table and tells nobody. So movement is noticed by
    reading, on the drain the UI already performs."""

    def test_the_drain_polls_the_calls_first(self):
        """One observer, feeding the one queue the UI drains. A timer of its
        own would be a second thing to start, stop and leak -- and polling
        AFTER the drain would delay every transition by a tick."""
        import inspect
        from android_bridge.connection import ConnectionController
        body = inspect.getsource(ConnectionController.drain_events)
        assert "poll_calls()" in body, (
            "nothing polls the call state, so the screen never learns a call "
            "moved")
        assert body.index("poll_calls()") < body.index("_events.drain"), (
            "call state is polled after the drain, so every transition waits "
            "a tick")

    def test_a_failed_poll_does_not_cost_the_ui_its_messages(self, pair):
        """The drain is how every message reaches the screen. A call-state
        read must not be able to take it down."""
        from android_bridge.connection import ConnectionController, SamProbe
        from android_bridge.settings import ConnectionProfile

        def explode():
            raise RuntimeError("no")

        pair.alice.poll_calls = explode
        controller = ConnectionController(
            pair.alice, ConnectionProfile(jid=pair.alice_jid, server="s.i2p"),
            transport_factory=lambda *a, **k: None,
            prober=lambda _p: SamProbe(True, "ok", "fine", "3.1"))
        assert controller.drain_events() == []

    def test_a_transition_is_announced_once(self, pair):
        """Emitted on movement, not on every poll: a UI that got an event per
        poll would redraw forever and could not tell movement from noise."""
        bridge = pair.alice.calls
        bridge._manager = _FakeCalls({pair.bob_jid: "RINGING"})
        before = len(pair.alice_sink.events)
        bridge.poll()
        bridge.poll()
        bridge.poll()
        announced = [e for e in pair.alice_sink.events[before:]
                     if isinstance(e, CallStateChanged)]
        assert len(announced) == 1, (
            "one transition produced %d events" % len(announced))
        assert announced[0].state is CallState.RINGING

    def test_a_finished_call_is_announced_as_idle(self, pair):
        """Without this the last state announced stays on the screen after
        the call has gone."""
        bridge = pair.alice.calls
        manager = _FakeCalls({pair.bob_jid: "ACTIVE"})
        bridge._manager = manager
        bridge.poll()
        manager._calls.clear()
        bridge.poll()
        states = [e.state for e in pair.alice_sink.events
                  if isinstance(e, CallStateChanged)]
        assert states[-1] is CallState.IDLE

    def test_the_duration_starts_at_active_and_not_before(self, pair):
        """`VoiceCallSession._call_t0` is set in its constructor -- it is the
        frame-timestamp origin, and the tunnel build is 30-120 s. Counting
        from it would show a minute and a half of talking that never
        happened."""
        bridge = pair.alice.calls
        manager = _FakeCalls({pair.bob_jid: "INVITING"})
        bridge._manager = manager
        bridge.poll()
        assert bridge.duration_seconds(pair.bob_jid) == 0

        manager._calls[pair.bob_jid].state = "ACTIVE"
        bridge.poll()
        # Zero seconds have passed, but the clock is now running rather than
        # absent -- which is the distinction that matters.
        assert pair.bob_jid in bridge._active_since

        manager._calls[pair.bob_jid].state = "ENDING"
        bridge.poll()
        assert bridge.duration_seconds(pair.bob_jid) == 0, (
            "the clock kept running after the call stopped being active")


class _FakeSession:
    """A session object with the one attribute the bridge reads.

    NOT a fake call manager in the sense the brief forbids: no call logic is
    replaced. These tests are about the bridge's own polling -- when it
    announces, and when it does not -- and driving real state transitions
    would need SAM, a router and a second handset.
    """

    def __init__(self, state):
        self.state = state


class _FakeCalls:
    def __init__(self, states):
        self._calls = {peer: _FakeSession(state)
                       for peer, state in states.items()}


class TestTheCallLoopIsClosedNotAbandoned:
    """Stopping an event loop does not release it: its selector and
    self-pipe stay open until `close`. `shutdown` stopped and joined but
    never closed, and the garbage collector reported it as "Exception
    ignored in BaseEventLoop.__del__" -- one leaked pipe pair per sign-out."""

    def test_the_loop_is_closed_after_shutdown(self, pair):
        bridge = pair.alice.calls
        bridge._ensure_manager()
        loop = bridge._loop
        assert loop is not None and not loop.is_closed()
        pair.alice.shutdown()
        assert loop.is_closed(), "the call loop was stopped but never closed"


class TestAnIncomingCallRingsThePhone:
    """`ChatState.handle` returns false for call events, so a call arriving
    in the background produced no notification at all and was usually timed
    out before anybody saw it. RINGING is safe to announce because it is
    unreachable by an unverified peer -- `_on_invite` refuses before a
    session exists, which `TestTheSmpGate` drives with a real INVITE."""

    @staticmethod
    @pytest.fixture(scope="class")
    def service():
        return _kt("connection", "OtrConnectionService.kt")

    def test_the_drain_acts_on_ring_changes(self, service):
        drain = service[service.index("if (chat.handle(event)) announceArrival()"):]
        drain = drain[:drain.index("delay(DRAIN_INTERVAL_MS)")]
        assert "chat.takeRingChanges()" in drain
        assert "announceCall()" in drain and "cancelCallNotification()" in drain

    def test_the_ring_says_nothing_about_who(self, service):
        body = service[service.index("private fun announceCall()"):]
        body = body[:body.index("private fun cancelCallNotification()")]
        assert "VISIBILITY_SECRET" in body, (
            "the call notification is visible on a locked screen")
        for leak in ("peer", "jid", "displayName", "setContentText(peer"):
            assert leak not in body.replace("R.string.call_incoming", ""), (
                "the call notification could carry %r" % leak)

    def test_there_is_no_full_screen_call_ui(self, service):
        """DECIDED, not forgotten. A full-screen intent puts a call screen
        over the lock screen: a disclosure that somebody is calling this
        device, visible to whoever holds it, and on Android 14+ a separate
        permission Play restricts. The heads-up notification rings just as
        loudly and shows nothing. See CallAlert.kt and the device test doc."""
        assert "setFullScreenIntent" not in service
        manifest = open(os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), "android", "app", "src", "main",
            "AndroidManifest.xml"), encoding="utf-8").read()
        assert "USE_FULL_SCREEN_INTENT" not in manifest

    def test_the_call_channel_is_secret_on_the_lock_screen(self, service):
        channel = service[service.index("CALL_CHANNEL_ID,"):]
        channel = channel[:channel.index("createNotificationChannels")]
        assert "lockscreenVisibility = Notification.VISIBILITY_SECRET" in channel

    def test_logout_takes_the_ring_down(self, service):
        logout = service[service.index("ACTION_LOGOUT ->"):]
        logout = logout[:logout.index("ACTION_START ->")]
        assert "cancelCallNotification()" in logout

    def test_the_call_strings_carry_no_format_arguments(self):
        import io as _io
        strings = _io.open(os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "android", "app", "src", "main", "res", "values", "strings.xml"),
            encoding="utf-8").read()
        import re
        for name in ("call_incoming", "call_channel_name",
                     "call_channel_description"):
            value = re.search(r'name="%s">([^<]*)<' % name, strings).group(1)
            assert "%" not in value, (
                "%s takes a format argument, which is where a name would go"
                % name)

    def test_changes_are_decided_by_a_tested_leaf(self):
        leaf = _kt("crypto", "CallAlert.kt")
        for line in leaf.splitlines():
            if line.startswith("import "):
                assert line.startswith("import org.otrv4plus."), line
        assert os.path.exists(os.path.join(ANDROID_TESTS, "crypto",
                                           "CallAlertTest.kt"))

    def test_a_ringing_call_is_stopped_when_the_account_changes(self):
        state = _kt("chat", "ChatState.kt")
        bind = state[state.index("fun bindAccount("):]
        bind = bind[:bind.index("callStates.clear()")]
        assert "CallAlert.Change.STOP" in bind, (
            "a call ringing for one account keeps ringing for the next")
