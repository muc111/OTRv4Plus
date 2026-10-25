# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""One router decision for Create account, Log in, and the sign-in after it.

Owner (2026-10-25): "if i2pd or i2p app is running in background we connect
via this app ... using SAM. If no SAM available then we run bundled router and
connect via SAM. Connection must cover new account creation and normal login
and also login following new account created." Two regressions broke that:

* Create account ran outside the connection service, so with no I2P app the
  built-in router never started and new testers could not make an account.
* After an account was created through i2pd, the sign-in that followed
  started the built-in router: i2pd's bridge, busy, answered the probe late.

These pin the wiring; RouterChoiceTest and RegisterRetryTest run the rules.
"""
import io
import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
JAVA = os.path.join(ROOT, "android", "app", "src", "main", "java", "org", "otrv4plus", "android")


def _read(*parts):
    with io.open(os.path.join(JAVA, *parts), encoding="utf-8") as fh:
        return fh.read()


def _code(text):
    text = re.sub(r"/\*(?:.|\n)*?\*/", " ", text)
    return re.sub(r"//[^\n]*", "", text)


SERVICE = _code(_read("connection", "OtrConnectionService.kt"))
VIEWMODEL = _code(_read("ConnectionViewModel.kt"))
CHOICE = _code(_read("connection", "RouterChoice.kt"))


def _fn(src, signature):
    start = src.index(signature)
    depth, i = 0, src.index("{", start)
    for j in range(i, len(src)):
        depth += {"{": 1, "}": -1}.get(src[j], 0)
        if depth == 0:
            return src[start:j + 1]
    raise AssertionError(signature)


def _router_then(fn, call):
    assert "chooseRouter()" in fn
    assert fn.index("chooseRouter()") < fn.index("prepareConnection(jid.trim(), server.trim(), samPort = samPort)")
    assert fn.index("prepareConnection(jid.trim(), server.trim(), samPort = samPort)") < fn.index(call)


def test_log_in_chooses_the_router_before_connecting():
    _router_then(_fn(SERVICE, "private suspend fun connectLoop()"), "core.connect(password)")


def test_create_account_chooses_the_router_before_registering():
    _router_then(_fn(SERVICE, "private suspend fun registerWhenReachable()"),
                 "core.register(password)")


def test_the_sign_in_after_a_new_account_is_the_ordinary_one():
    start = _fn(SERVICE, "private fun startRegistration()")
    ok = start[start.index("if (out.ok)"):]
    assert "startConnection()" in ok, "the same connectLoop, so the same router choice"


def test_nothing_outside_the_service_registers():
    """The bypass that broke sign-up: registration from the screen, with no router."""
    assert not re.search(r"\b(c|core)\.register\(", VIEWMODEL)
    regs = [m.start() for m in re.finditer(r"core\.register\(", SERVICE)]
    fn = _fn(SERVICE, "private suspend fun registerWhenReachable()")
    assert len(regs) == 1 and fn.count("core.register(") == 1


def test_the_choice_remembers_the_phones_router():
    choose = _fn(SERVICE, "private suspend fun chooseRouter()")
    assert "RouterChoice.decide(probe, router.available, externalSamSeen)" in choose
    assert "RouterChoice.Probe.SAM -> externalSamSeen = true" in choose
    assert "RouterChoice.Probe.NO_ANSWER -> externalSamSeen = false" in choose
    assert choose.index("findExternalSam()") < choose.index("router.launch()")


def test_a_slow_bridge_is_not_mistaken_for_no_router():
    probe = _fn(CHOICE, "fun probeSam(")
    assert "catch (_: java.net.SocketTimeoutException)" in probe
    assert "if (connected) Probe.SLOW else Probe.NO_ANSWER" in probe
    assert "val PROBE_TIMEOUTS_MS = intArrayOf(1_500, 3_000, 6_000)" in CHOICE


def test_sign_out_forgets_the_phones_router():
    stop = _fn(SERVICE, "fun stopConnection(")
    assert "externalSamSeen = false" in stop


def test_the_drain_slows_in_the_background():
    """Battery (owner, 2026-10-25): the 500 ms pass, four calls into Python,
    ran with the screen off too. DrainPaceTest runs the rule."""
    drain = _fn(SERVICE, "private fun startDraining()")
    assert "DrainPace.readsState(tick, visible, inCall)" in drain
    assert "delay(DrainPace.intervalMs(visible, inCall))" in drain
    assert "DRAIN_INTERVAL_MS" not in drain
