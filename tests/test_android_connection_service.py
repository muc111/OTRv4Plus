# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""The connection outlives the screen.

WHY THE SERVICE EXISTS

`ConnectionViewModel` held the core, which survives Activity recreation and
therefore fixed the rotation bug it was written for. It does not survive the
PROCESS, and Android kills a backgrounded process that nothing is holding up.
So the connection died whenever the user looked at something else, the I2P
tunnel went with it, and every message sent in the meantime was lost.

These are structural: a `Service` cannot be instantiated under pytest, and the
Android instrumentation tests need a device. The decisions that CAN be executed
-- reconnect backoff, single-flight, the disconnect latch, phase mapping -- are
in `ReconnectPolicyTest` and `LinkPhaseTest`, which CI runs on the JVM. What is
asserted here is the wiring those decisions hang from, and the manifest facts
that no unit test can see.
"""

import io
import os
import re

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ANDROID = os.path.join(ROOT, "android", "app", "src", "main")
JAVA = os.path.join(ANDROID, "java", "org", "otrv4plus", "android")


def _read(*parts):
    with io.open(os.path.join(*parts), encoding="utf-8") as fh:
        return fh.read()


def _code_only(text):
    text = re.sub(r"/\*(?:.|\n)*?\*/", " ", text)
    text = re.sub(r"//[^\n]*", "", text)
    return re.sub(r'"(?:\\.|[^"\\\n])*"', '""', text)


@pytest.fixture(scope="module")
def service():
    return _read(JAVA, "connection", "OtrConnectionService.kt")


@pytest.fixture(scope="module")
def manifest():
    return _read(ANDROID, "AndroidManifest.xml")


class TestTheManifestDeclaresIt:

    def test_the_service_is_declared(self, manifest):
        assert ".connection.OtrConnectionService" in manifest

    def test_it_is_not_exported(self, manifest):
        """The Intent that starts it carries the account password. An exported
        service would be an invitation to send one."""
        block = manifest[manifest.index("OtrConnectionService"):]
        block = block[:block.index("/>")]
        assert 'android:exported="false"' in block

    def test_it_declares_a_foreground_type(self, manifest):
        """Required from API 34, and `dataSync` is the honest one: a long-lived
        network session the user asked for. It is not a media, location or call
        service and must not claim to be."""
        block = manifest[manifest.index("OtrConnectionService"):]
        block = block[:block.index("/>")]
        assert 'android:foregroundServiceType="dataSync"' in block

    def test_the_permissions_are_declared(self, manifest):
        for permission in ("FOREGROUND_SERVICE",
                           "FOREGROUND_SERVICE_DATA_SYNC",
                           "POST_NOTIFICATIONS"):
            assert "android.permission.%s" % permission in manifest, permission

    def test_no_wake_lock_is_requested(self, manifest):
        """A foreground service is the supported mechanism. A wakelock on top
        would be holding the CPU awake to work around the platform rather than
        with it."""
        assert "WAKE_LOCK" not in manifest


class TestItOwnsTheConnection:

    def test_it_holds_the_only_core(self, service):
        assert "val core: ChaquopyOtrCore by lazy" in service

    def test_it_uses_the_tested_reconnect_policy(self, service):
        """The backoff, the single-flight gate and the disconnect latch are
        decisions with executed tests. Reimplementing them here would put them
        beyond reach again."""
        assert "ReconnectPolicy()" in service
        code = _code_only(service)
        assert "beginAttempt()" in code
        assert "endAttempt()" in code
        assert "nextDelayMs()" in code

    def test_an_explicit_stop_latches_the_policy(self, service):
        block = service[service.index("fun stopConnection("):]
        block = block[:block.index("private suspend fun connectLoop")]
        assert "onUserDisconnect()" in block

    def test_a_dropped_stream_is_not_an_explicit_stop(self, service):
        """`stopConnection(explicit = ...)` is the distinction. A drop we did
        not ask for must still reconnect."""
        assert "explicit: Boolean" in service
        assert "if (explicit) reconnect.onUserDisconnect()" in service

    def test_every_call_into_python_is_off_the_main_thread(self, service):
        """Chaquopy's JNI calls block and are not interruptible. One on the
        main thread is an ANR, not a slow connect.

        `core.note` is the one exception, and it is not really one: it only
        enqueues onto a single-thread executor and returns, so no JNI crossing
        happens on the caller's thread. The next test pins that, because the
        exception is only safe for as long as it stays true.
        """
        assert "Dispatchers.IO" in service
        code = _code_only(service)
        stray = [call for call in
                 re.findall(r"^\s{0,12}core\.\w+\(", code, re.M)
                 if "core.note(" not in call]
        assert not stray, stray

    def test_note_is_the_only_exception_and_it_does_not_block(self):
        """It is called from onStartCommand, onDestroy and the phase machine
        -- all main thread. If it ever crosses into Python inline, every one
        of those becomes an ANR risk."""
        import io as _io
        import os as _os
        root = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
        with _io.open(_os.path.join(
                root, "android", "app", "src", "main", "java", "org",
                "otrv4plus", "android", "bridge", "ChaquopyOtrCore.kt"),
                encoding="utf-8") as fh:
            core = fh.read()
        body = core[core.index("fun note(component: String"):]
        body = body[:body.index("\n    /**")]
        assert "notes.execute {" in body, (
            "note() crosses into Python on the calling thread")
        assert body.index("notes.execute {") < body.index('callAttr("note"')

    def test_the_note_worker_keeps_events_in_order(self):
        """A trace out of order is worse than no trace: the sequence IS the
        diagnosis."""
        import io as _io
        import os as _os
        root = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
        with _io.open(_os.path.join(
                root, "android", "app", "src", "main", "java", "org",
                "otrv4plus", "android", "bridge", "ChaquopyOtrCore.kt"),
                encoding="utf-8") as fh:
            core = fh.read()
        block = core[core.index("private val notes:"):]
        block = block[:block.index("\n    }")]
        assert "ThreadPoolExecutor(\n            1, 1," in block, (
            "more than one note thread, so the order is whatever the "
            "scheduler felt like")
        assert "isDaemon = true" in block, (
            "a non-daemon logging thread holds the process open at shutdown")

    def test_the_event_time_is_taken_before_the_hand_off(self):
        """Otherwise every Kotlin-side entry is stamped with the moment the
        worker got round to it, and the timeline is fiction."""
        import io as _io
        import os as _os
        root = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
        with _io.open(_os.path.join(
                root, "android", "app", "src", "main", "java", "org",
                "otrv4plus", "android", "bridge", "ChaquopyOtrCore.kt"),
                encoding="utf-8") as fh:
            core = fh.read()
        body = core[core.index("fun note(component: String"):]
        body = body[:body.index("\n    /**")]
        assert "val at = System.currentTimeMillis()" in body
        assert body.index("val at =") < body.index("notes.execute {")

    def test_stopping_releases_the_transport_and_the_tunnel(self, service):
        block = service[service.index("fun stopConnection("):]
        block = block[:block.index("private suspend fun connectLoop")]
        assert "cancelConnect" in block
        assert "disconnect" in block

    def test_it_is_not_sticky(self, service):
        """START_STICKY would have Android restart it with a null Intent and
        therefore no credentials -- a notification attached to nothing."""
        assert "START_NOT_STICKY" in service
        assert "START_STICKY" not in _code_only(service).replace(
            "START_NOT_STICKY", "")


class TestTheViewModelOnlyBinds:

    @staticmethod
    @pytest.fixture(scope="class")
    def view_model():
        return _read(JAVA, "ConnectionViewModel.kt")

    def test_it_binds_rather_than_constructing(self, view_model):
        assert "bindService" in view_model
        assert "ChaquopyOtrCore(" not in _code_only(view_model)

    def test_binding_auto_creates_the_service(self, view_model):
        """So the core exists for the router probe before anyone has asked to
        connect -- and the notification appears only when a connection does."""
        assert "BIND_AUTO_CREATE" in view_model

    def test_clearing_it_only_unbinds(self, view_model):
        cleared = view_model[view_model.index("override fun onCleared"):]
        assert "unbindService" in cleared
        for teardown in ("disconnect()", "shutdown()"):
            assert teardown not in cleared, teardown

    def test_the_core_is_nullable(self, view_model):
        """There is a window between the ViewModel being created and the
        binding landing. Pretending otherwise hands callers an object that is
        not there yet."""
        assert "ChaquopyOtrCore?" in view_model


class TestNothingSensitiveLeaves:

    def test_the_notification_carries_no_identity(self, service):
        """It is visible on a locked screen. Who someone talks to is the thing
        this client protects."""
        block = service[service.index("private fun buildNotification"):]
        block = block[:block.index("private fun phaseText")]
        for leak in ("jid", "status.jid", "peer", "server"):
            assert leak not in block, leak

    def test_the_notification_is_secret_on_the_lock_screen(self, service):
        assert "VISIBILITY_SECRET" in service

    def test_the_password_is_removed_from_the_intent(self, service):
        """Intents can be logged by the system. It does not sit in one any
        longer than it must."""
        assert "removeExtra(EXTRA_PASSWORD)" in service

    def test_the_password_is_never_logged_or_shown(self, service):
        code = _code_only(service)
        for line in code.splitlines():
            if "password" in line.lower():
                assert "Log." not in line, line
                assert "setContentText" not in line, line

    def test_failures_are_codes_not_exception_text(self, service):
        """A PyException carries the engine's own message."""
        assert "simpleName" in service
        assert not re.search(r"\.message\b(?!\()", _code_only(service))


class TestItDoesNotConnectBeforeThereIsAnAccount:
    """THE LAUNCH BUG. The app tried to connect the moment it was opened.

    On a fresh install the only route to the login form was: wait for the
    attempt, press Cancel, then sign in.

    `onStartCommand`'s ACTION_START branch read

        if (account.isNotBlank()) { ... } else { credentials.load()?.let { ... } }
        startConnection()

    with `startConnection()` OUTSIDE the `else`. `load()` returns null when
    nothing is stored, so a first launch fell through the `let`, left `jid`
    as "", and connected as nobody: the reconnect suppression latch cleared,
    CONNECTING entered, `prepareConnection("", "")` building I2P tunnels, a
    failure, and then a backoff loop -- which is why it could not be waited
    out.

    The decision now lives in `connection/Startup.kt`, which is plain Kotlin
    and is EXECUTED by `StartupTest` on the JVM. What is guarded here is that
    the service asks it, and that the guard did not simply move to the screen.
    """

    @staticmethod
    @pytest.fixture(scope="class")
    def start_branch(service):
        """The ACTION_START arm of onStartCommand, comments stripped."""
        code = _code_only(service)
        start = code.index("ACTION_START ->")
        return code[start:code.index("else ->", start)]

    def test_the_decision_is_a_plain_kotlin_leaf(self):
        """Not a condition inlined in the service: a Service cannot be
        instantiated under pytest and needs a device for instrumentation, so a
        rule written there is reviewed rather than run."""
        startup = _read(JAVA, "connection", "Startup.kt")
        imports = re.findall(r"^import\s+([\w.]+)", _code_only(startup), re.M)
        assert imports == [], (
            "Startup imports %s, so it can no longer be unit-tested without "
            "an Android build" % imports)

    def test_the_rule_has_executed_tests(self):
        tests = _read(ROOT, "android", "app", "src", "test", "java", "org",
                      "otrv4plus", "android", "connection", "StartupTest.kt")
        for covered in (
            "a first launch with nothing stored does not connect",
            "an explicit connect starts",
            "a remembered account still connects on launch",
        ):
            assert covered in tests, (
                "the JVM test for '%s' is gone; that case is the one the "
                "fix must not break" % covered)

    def test_the_service_asks_it(self, start_branch):
        assert "Startup.accountFor(" in start_branch

    def test_no_account_means_no_attempt(self, start_branch):
        """The defect, stated structurally: `startConnection()` must not be
        reachable when the decision found nothing to connect as."""
        assert "if (chosen == null)" in start_branch
        refusal = start_branch[start_branch.index("if (chosen == null)"):]
        refusal = refusal[:refusal.index("}", refusal.index("idle()"))]
        assert "idle()" in refusal
        assert "return" in refusal
        assert "startConnection()" not in refusal

    def test_the_attempt_is_started_once_and_after_the_decision(
            self, start_branch):
        assert start_branch.count("startConnection()") == 1
        assert start_branch.index("Startup.accountFor(") < \
            start_branch.index("startConnection()")

    def test_standing_down_is_not_reported_as_a_failure(self, service):
        """Nothing failed. A first launch with no stored account is the
        ordinary case, and FAILED would put an error above an empty login
        form and hand `LoginProgress.problemToShow` a problem the user never
        caused."""
        code = _code_only(service)
        idle = code[code.index("private fun idle()"):]
        idle = idle[:idle.index("private fun createChannel")]
        assert "LinkPhase.STOPPED" in idle
        assert "LinkPhase.FAILED" not in idle

    def test_standing_down_takes_the_notification_down(self, service):
        """A persistent connection notification in the shade of somebody who
        has not signed in is a statement about work that is not happening."""
        code = _code_only(service)
        idle = code[code.index("private fun idle()"):]
        idle = idle[:idle.index("private fun createChannel")]
        assert "stopForeground" in idle

    def test_the_fix_is_not_a_guard_on_the_screen(self):
        """A UI condition would leave the service's own resume path -- and any
        restart that does not come from the Activity -- still able to connect
        as nobody, and the rule would be stated in two places that can
        disagree."""
        activity = _code_only(_read(JAVA, "MainActivity.kt"))
        assert "resumeIfRemembered()" in activity, (
            "the resume was removed rather than made conditional; a "
            "remembered session must still come back on launch")

    def test_the_resume_path_still_exists_end_to_end(self, service):
        """Case three of the brief: a persisted session reconnects. The chain
        is `resumeIfRemembered` -> `resume()` -> ACTION_START with no extras
        -> stored credentials -> connect."""
        vm = _code_only(_read(JAVA, "ConnectionViewModel.kt"))
        assert "OtrConnectionService.resume(" in vm
        assert "fun resume(context: Context)" in service
        assert "credentials.load()" in _code_only(service)
