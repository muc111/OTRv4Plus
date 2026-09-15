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
        main thread is an ANR, not a slow connect."""
        assert "Dispatchers.IO" in service
        stray = re.findall(r"^\s{0,12}core\.\w+\(", _code_only(service), re.M)
        assert not stray, stray

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
