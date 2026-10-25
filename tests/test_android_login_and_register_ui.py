# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Two buttons on the login screen, and nothing technical anywhere near them.

WHAT THESE TESTS CAN AND CANNOT DO
----------------------------------
Compose cannot be compiled in this environment -- `dl.google.com` is blocked,
so the Android Gradle Plugin does not resolve and there is no way to run a
composable here. These read the source. That is genuinely weaker than
executing it, and the project's answer to that weakness is to keep the
DECISIONS out of the composables: `SignIn` decides what a typed name resolves
to, `RegistrationOutcome` decides where a failure points the user, and both are
plain Kotlin with tests that run. What is left in the composable is layout, and
layout is what these files check.

WHAT THEY ARE CHECKING FOR
--------------------------
The login screen used to render the SAM probe's raw output, the failure code,
whether the transport's worker thread was alive, and `inputs` -- the literal
arguments that crossed into the transport. All of it is useful and none of it
belongs in front of somebody signing in: a login screen that says
`stream_failed` and `worker thread: alive` reads as broken even when it is
working, and it teaches people to ignore the words on it.

It moved to the Debug screen. These tests are what keeps it from moving back.
"""

import os
import re
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

UI = os.path.join(ROOT, "android", "app", "src", "main", "java", "org",
                  "otrv4plus", "android")
CONNECT = os.path.join(UI, "ui", "ConnectScreen.kt")
DEBUG = os.path.join(UI, "ui", "DevShellScreen.kt")
VIEWMODEL = os.path.join(UI, "ConnectionViewModel.kt")
BRIDGE = os.path.join(UI, "bridge", "ChaquopyOtrCore.kt")
MAIN = os.path.join(UI, "MainActivity.kt")


def read(path):
    with open(path, encoding="utf-8") as handle:
        return handle.read()


def code_of(path):
    """The source with comments and docstrings stripped.

    Necessary rather than fastidious: every one of these files EXPLAINS the
    thing it no longer does, at length, and a test searching the raw text for
    "worker thread" finds the comment saying it was removed.
    """
    text = read(path)
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return "\n".join(line for line in text.splitlines()
                     if not line.lstrip().startswith("//"))


def body_of(text, signature):
    """The body of the function whose declaration contains *signature*.

    By brace matching rather than by looking for the next `/**`, because
    [code_of] has already removed the doc comments that would have delimited
    it -- an earlier version of this helper searched for one and raised
    ValueError on every file it was given.
    """
    start = text.index(signature)
    open_brace = text.index("{", start)
    depth = 0
    for i in range(open_brace, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[open_brace:i + 1]
    raise AssertionError("unbalanced braces after %r" % signature)


@pytest.fixture(scope="module")
def connect():
    return code_of(CONNECT)


@pytest.fixture(scope="module")
def debug():
    return code_of(DEBUG)


# ── two buttons ──────────────────────────────────────────────────────────────

class TestTheTwoActions:

    def test_there_is_a_log_in_button(self, connect):
        assert 'Text("Log in")' in connect

    def test_there_is_a_create_account_button(self, connect):
        assert 'Text("Create account")' in connect

    def test_log_in_calls_connect(self, connect):
        assert "model.connect(" in connect

    def test_create_account_calls_register(self, connect):
        assert "model.register(" in connect

    def test_create_account_does_not_then_sign_in(self, connect):
        """Two operations, two outcomes. Folded together, a registration that
        worked and a login that did not would have one outcome between them
        and the user could not tell which half went wrong."""
        block = connect[connect.index("model.register("):]
        block = block[:block.index("}")]
        assert "model.connect(" not in block

    def test_both_clear_the_password_field(self, connect):
        """A rejected password is a reason to retype it, and a created account
        has no further use for it on this screen."""
        for call in ("model.connect(", "model.register("):
            block = connect[connect.index(call):]
            block = block[:block.index("}") + 1]
            assert "password = \"\"" in block, call

    def test_neither_is_offered_without_a_resolved_target(self, connect):
        assert "target != null" in connect
        assert "password.isNotBlank()" in connect

    def test_neither_is_offered_while_something_is_running(self, connect):
        assert "busy == null" in connect

    def test_create_account_is_the_secondary_action(self, connect):
        """Almost every press here is a login; account creation happens once.
        Giving both the same weight makes the commoner action the one you have
        to look for."""
        filled = connect.index('Text("Log in")')
        outlined = connect.index('Text("Create account")')
        assert filled < outlined
        between = connect[filled:outlined]
        assert "OutlinedButton" in between


class TestTheRegistrationResultIsItsOwnThing:

    def test_the_screen_reads_it_from_the_view_model(self, connect):
        assert "model.registration" in connect

    def test_a_success_says_the_account_was_created(self, connect):
        assert "Account created" in connect

    def test_a_success_signs_in_and_does_not_ask_for_log_in(self, connect):
        """Owner (2026-10-25): create the account, then sign in by itself.
        "Now press Log in" is gone; the sign-in progress follows instead."""
        assert not re.search(r"press Log in", connect)
        assert "model.cancelRegister()" in connect

    def test_a_failure_shows_the_sentence_python_chose(self, connect):
        assert "it.detail" in connect

    def test_registered_has_a_human_stage_label(self, connect):
        assert '"registered" ->' in connect
        label = re.search(r'"registered" -> "([^"]+)"', connect).group(1)
        assert "not signed in" in label.lower(), (
            "the account exists and nobody is logged in; a label that said "
            "'Disconnected' would mean the opposite thing to somebody who "
            "had just pressed Create account")


# ── the debug text is gone from the login screen ─────────────────────────────

class TestNothingTechnicalOnTheLoginScreen:

    @pytest.mark.parametrize("gone", [
        "What reached the transport",
        "status.inputs",
        "status.workerAlive",
        "SAM version",
        "Check router",
        "model.checkRouter",
        "status.code",
        "model.probe",
    ])
    def test_it_is_not_there(self, connect, gone):
        assert gone not in connect, gone

    def test_the_failure_code_is_not_rendered(self, connect):
        assert 'StatusRow("Reason"' not in connect

    def test_the_router_probe_block_is_gone(self, connect):
        """The stage LABEL still mentions the router -- "Checking for an I2P
        router" is a sentence about what is happening. What is gone is the
        probe's own reachable/code/version/detail block."""
        assert 'StatusRow("Reachable"' not in connect
        assert "it.reachable" not in connect

    def test_the_remaining_state_line_is_a_sentence_not_a_stage(self, connect):
        """`stageLabel` is what turns `building_tunnels` into something a
        person can act on."""
        assert "stageLabel(status.stage)" in connect

    def test_a_connection_failure_still_says_something(self, connect):
        """Removing the technical text must not leave a failure silent: the
        line comes from ConnectProblem (rc.63), and an error still shows the
        transport's own sentence."""
        assert "ConnectProblem.line(" in connect
        assert "status.detail" in connect

    def test_debug_is_reachable_from_here(self, connect):
        assert 'Text("Debug")' in connect
        assert "onOpenDiagnostics" in connect


# ── and present on the debug screen ──────────────────────────────────────────

class TestTheDebugScreenCarriesWhatMoved:

    @pytest.mark.parametrize("present", [
        "What reached the transport",
        "status.inputs",
        "status.workerAlive",
        "SAM version",
        "status.code",
        "onCheckRouter",
    ])
    def test_it_is_there(self, debug, present):
        assert present in debug, present

    def test_it_takes_the_live_connection_state(self, debug):
        assert "status: ConnectionStatus" in debug

    def test_it_takes_the_router_probe(self, debug):
        assert "probe: RouterProbe?" in debug

    def test_the_connection_is_shown_before_the_startup_snapshot(self, debug):
        """The snapshot is taken at launch and is minutes old by the time
        anything goes wrong."""
        screen = debug[debug.index("fun DevShellScreen("):]
        assert screen.index("ConnectionDebug(status") < screen.index('Text("Start-up"')
        part = debug[debug.index("private fun ConnectionDebug("):]
        assert 'Text("Connection"' in part[:part.index("\n}\n")]

    def test_it_still_exports_the_error_log(self, debug):
        assert "DiagnosticsExport.share(" in debug
        assert "diagnosticReport()" in debug

    def test_it_still_offers_copy_as_a_fallback(self, debug):
        """A device with no mail or notes app has nothing to answer the share
        intent, and FLAG_SECURE means there is no screenshot either."""
        assert "diagnosticSummary()" in debug
        assert "clipboard.setText" in debug

    def test_main_activity_hands_it_the_state(self):
        text = code_of(MAIN)
        block = text[text.index("DevShellScreen("):]
        block = block[:block.index(")\n")]
        for arg in ("status =", "probe =", "onCheckRouter ="):
            assert arg in block, arg


# ── the bridge and the view model ────────────────────────────────────────────

class TestTheViewModelPath:

    @pytest.fixture(scope="class")
    @classmethod
    def model(cls):
        return code_of(VIEWMODEL)

    def test_register_exists(self, model):
        assert "fun register(" in model

    def test_it_goes_through_the_service_which_finds_the_router(self, model):
        """Owner (2026-10-25): registration ran outside the service, so it never
        started the built-in router and failed "could not reach the server"
        whenever the I2P app was not running. It is handed to the service, which
        chooses and waits for the router as Log in does."""
        block = body_of(model, "fun register(")
        assert "OtrConnectionService.start(" in block and "register = true" in block
        assert "c.register(" not in block, "no registration from the screen any more"

    def test_the_service_waits_for_the_router_then_registers_then_signs_in(self):
        svc = code_of(os.path.join(UI, "connection", "OtrConnectionService.kt"))
        reg = body_of(svc, "private suspend fun registerWhenReachable()")
        assert "withContext(Dispatchers.IO)" in reg, "a blocking JNI call off the main thread"
        assert reg.index("chooseRouter()") < reg.index("core.register(password)")
        assert reg.index("prepareConnection(jid.trim(), server.trim(), samPort = samPort)") \
            < reg.index("core.register(password)")
        assert "RegisterRetry.again(" in reg
        start = body_of(svc, "private fun startRegistration()")
        ok = start[start.index("if (out.ok)"):]
        assert ok.index("credentials.save(") < ok.index("startConnection()")
        assert "registration = out" in start[start.index("} else {"):]

    def test_credentials_are_saved_only_once_the_account_exists(self):
        svc = code_of(os.path.join(UI, "connection", "OtrConnectionService.kt"))
        start = svc[svc.index("ACTION_START ->"):]
        branch = start[start.index("if (register) {"):start.index("return START_NOT_STICKY", start.index("if (register) {"))]
        assert "credentials.save" not in branch and "startRegistration()" in branch

    def test_it_is_refused_while_connected(self, model):
        """`prepareConnection` replaces the core's controller. Doing that
        under a live session leaves the service holding a connection nothing
        can any longer disconnect."""
        block = body_of(model, "fun register(")
        assert "status.connected" in block

    def test_the_result_is_its_own_state(self, model):
        assert "var registration by mutableStateOf<RegistrationOutcome?>" in model

    def test_the_password_is_not_stored(self, model):
        block = body_of(model, "fun register(")
        assert not re.search(r"this\.password\s*=", block)


class TestTheBridgeCall:

    @pytest.fixture(scope="class")
    @classmethod
    def bridge(cls):
        return code_of(BRIDGE)

    def test_it_calls_the_controller(self, bridge):
        assert 'callAttr("register", password)' in bridge

    def test_it_returns_a_registration_outcome(self, bridge):
        assert "fun register(password: String): RegistrationOutcome" in bridge

    def test_an_unprepared_core_is_a_named_failure(self, bridge):
        block = body_of(bridge, "fun register(password")
        assert 'OtrBridgeException("not_prepared")' in block

    def test_a_missing_code_becomes_unknown_rather_than_blank(self, bridge):
        block = body_of(bridge, "fun register(password")
        assert 'ifBlank { "unknown" }' in block
