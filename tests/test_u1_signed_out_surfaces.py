# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""U1 -- nothing signed-in, and no device fingerprint, while signed out.

Device report (2026-10-26): signed out (not wiped), Sign in -> About & licences
-> back landed on the empty chat list, from where the device's identity
fingerprint could be read. That fingerprint is device-binding material: read
before a login, it can later be matched with the server's record of a login
from this device. The gate is in the bridge (`OtrApp.local_fingerprint` is ""
until a login succeeds), and the screens are gated on top of it.

  U1-T1  back from About while signed out goes to sign-in;
  U1-T2  no signed-in screen shows while signed out, and sign-out leaves none;
  U1-T3  Android: no path gives the fingerprint while signed out;
  U1-T4  desktop and terminal: the same;
  U1-T5  a successful login brings it back, where it belongs;
  U1-T6  another account after sign-out inherits nothing shown before.

The navigation rules run in `AuthGateTest` (JVM).
"""
import io
import os
import re
import types

import pytest

import test_smp_end_to_end as E

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
A = os.path.join(ROOT, "android", "app", "src", "main", "java", "org", "otrv4plus", "android")
D = os.path.join(ROOT, "desktop", "src", "main", "kotlin", "org", "otrv4plus", "desktop")


def _read(*parts):
    with io.open(os.path.join(*parts), encoding="utf-8") as fh:
        return fh.read()


def _code(text):
    text = re.sub(r"/\*(?:.|\n)*?\*/", " ", text)
    return re.sub(r"//[^\n]*", "", text)


MAIN = _read(A, "MainActivity.kt")


@pytest.fixture
def app():
    from android_bridge.app import OtrApp
    a = OtrApp.__new__(OtrApp)
    a._engine = E._manager()
    a._signed_in = False
    a._wiped = False
    a._log = None
    return a


# ── U1-T1 ────────────────────────────────────────────────────────────────────

def test_u1_t1_about_goes_back_to_sign_in_while_signed_out():
    route = MAIN[MAIN.index("private fun AboutRoute("):]
    route = route[:route.index("\n    }\n")]
    assert "go(AuthGate.back(signedIn, Screen.CONVERSATIONS, Screen.CONNECT))" in route
    assert "BackHandler(onBack = back)" in route, "the swipe and the Back button alike"
    assert "AboutScreen(onBack = back)" in route
    assert "Screen.ABOUT -> AboutRoute(connection.signedIn) { screen = it }" in MAIN
    assert "BackHandler { screen = Screen.CONVERSATIONS }" not in MAIN


# ── U1-T2 ────────────────────────────────────────────────────────────────────

def test_u1_t2_only_public_screens_render_while_signed_out():
    assert ("private val PUBLIC_SCREENS = setOf(Screen.CONNECT, Screen.ABOUT, "
            "Screen.DIAGNOSTICS)") in MAIN
    assert ("when (AuthGate.shown(screen, connection.signedIn, PUBLIC_SCREENS, "
            "Screen.CONNECT).also { screen = it }) {") in MAIN
    assert len(re.findall(r"\bwhen \(screen\) \{", _code(MAIN))) == 0, "every screen goes through the gate"


def test_u1_t2_sign_out_keeps_nothing_to_navigate_back_to():
    reset = MAIN[MAIN.index("SignedOutReset(connection.signedIn) {"):].split("\n", 1)[0]
    for cleared in ("openJid = null", 'profileOf = ""', "lastTab = Screen.CONVERSATIONS",
                    "chat.forgetIdentity()"):
        assert cleared in reset
    assert "LaunchedEffect(signedIn) { if (!signedIn) reset() }" in MAIN


def test_u1_t2_signed_in_means_a_login_succeeded_for_this_account():
    svc = _code(_read(A, "connection", "OtrConnectionService.kt"))
    ok = svc[svc.index("reconnect.onConnected()"):]
    assert ok.index("signedIn = true") < ok.index("failure = null")
    enter = svc[svc.index("private fun enterAccount(next: AccountScope)"):]
    enter = enter[:enter.index("chat.bindAccount(next)")]
    assert "signedIn = false" in enter, "a new account, sign-out and wipe start signed out"
    wipe = svc[svc.index("private fun wipeAndExit("):]
    assert "signedIn = false" in wipe[:400]
    vm = _code(_read(A, "ConnectionViewModel.kt"))
    assert "signedIn = it.signedIn" in vm
    logout = vm[vm.index("fun logout()"):]
    assert "signedIn = false" in logout[:200], "dark at once, not on the next poll"


# ── U1-T3 ────────────────────────────────────────────────────────────────────

def test_u1_t3_the_bridge_gives_no_fingerprint_while_signed_out(app):
    assert app._engine.get_fingerprint(), "the engine has one"
    assert app.local_fingerprint() == ""
    details = app.security_details("bob@example.test")
    assert details.local_fingerprint == ""


def test_u1_t3_no_public_screen_reads_a_fingerprint():
    for parts in (("ui", "AboutScreen.kt"), ("ui", "ConnectScreen.kt"), ("ui", "DevShellScreen.kt")):
        path = os.path.join(A, *parts)
        if not os.path.exists(path):
            continue
        src = _code(_read(path))
        assert not re.search(r"(localFingerprint|ownFingerprint|local_fingerprint)", src), parts


def test_u1_t3_the_profile_forgets_what_it_showed():
    vm = _read(A, "chat", "ChatViewModel.kt")
    fn = vm[vm.index("fun forgetIdentity()"):]
    fn = fn[:fn.index("\n    }\n")]
    assert "profileIdentity = null" in fn and 'ownFingerprint = ""' in fn


# ── U1-T4 ────────────────────────────────────────────────────────────────────

def test_u1_t4_the_desktop_host_announces_no_fingerprint_before_login():
    from desktop_bridge import host as H
    from android_bridge.app import OtrApp
    lines = []
    h = H.Host.__new__(H.Host)

    def factory():
        a = OtrApp.__new__(OtrApp)
        a._engine = E._manager()
        a._signed_in = False
        a._wiped = False
        return a

    h._app_factory = factory
    h.send = lines.append
    h._safe = lambda fn, *a: fn(*a)
    h.start()
    assert lines[0]["ready"]["fingerprint"] == ""


def test_u1_t4_the_desktop_screens_show_none_before_login():
    connect = _code(_read(D, "ui", "ConnectScreen.kt"))
    assert "fingerprint" not in connect.lower()
    model = _code(_read(D, "AppModel.kt"))
    start = model[model.index("fun start()"):model.index("private fun runLoop()")]
    assert "core.localFingerprint()" not in start
    ok = model[model.index("if (status.connected) {"):]
    ok = ok[:ok.index("screen = Screen.MAIN")]
    assert "core.localFingerprint()" in ok, "fetched once authenticated"
    out = model[model.index("fun disconnect()"):]
    out = out[:out.index("\n    }\n")]
    assert out.index('fingerprint = ""') < out.index("core.disconnect()")


def test_u1_t4_the_terminal_withholds_it_until_signed_in(capsys):
    import otrv4plus_xmpp_trust as T
    me = types.SimpleNamespace(identity_persistent=True, _signed_in=False,
                               _local_fp=lambda peer=None: "AABBCCDD" * 14,
                               otr=types.SimpleNamespace(config=types.SimpleNamespace(identity_path="x")))
    owner = next(c for c in vars(T).values()
                 if isinstance(c, type) and "show_identity" in vars(c))
    try:
        owner.show_identity(me)
    except Exception:
        pass
    out = capsys.readouterr().out
    assert "AABBCCDD" not in out.replace(" ", "")
    assert "shown once you are signed in" in out
    term = _read(ROOT, "client", "otrv4plus_xmpp.py")
    start = term[term.index("    async def _on_start(self, event):"):][:400]
    assert "self._signed_in = True" in start
    cleanup = term[term.index("    def cleanup(self) -> None:"):][:500]
    assert "self._signed_in = False" in cleanup


# ── U1-T5 ────────────────────────────────────────────────────────────────────

def test_u1_t5_a_successful_login_brings_it_back(app):
    app.note_signed_in("alice@example.test")
    assert app.local_fingerprint() == app._engine.get_fingerprint() != ""
    assert app.security_details("bob@example.test").local_fingerprint == app.local_fingerprint()


def test_u1_t5_only_a_successful_connect_signs_in():
    conn = _read(ROOT, "android_bridge", "connection.py")
    ok = conn[conn.index("# U1: authenticated now, and only now"):]
    assert ok.index("signed_in(self._profile.jid") < ok.index('self._last = {"ok": True, "stage": "connected"')
    app = _read(ROOT, "android_bridge", "app_smp.py")
    fn = app[app.index("def note_signed_in("):app.index("def note_signed_out(")]
    assert '"@" in account' in fn, "a concrete account, not an attempt"


def test_u1_t5_an_address_that_is_not_an_account_signs_nobody_in(app):
    app.note_signed_in("")
    app.note_signed_in("not-an-address")
    assert app.local_fingerprint() == ""


# ── U1-T6 ────────────────────────────────────────────────────────────────────

def test_u1_t6_sign_out_then_another_account(app):
    app.note_signed_in("alice@example.test")
    assert app.local_fingerprint()
    app.note_signed_out()
    assert app.local_fingerprint() == "", "dark between accounts"
    app.note_signed_in("bob@example.test")
    assert app.local_fingerprint(), "the second account's own login"


def test_u1_t6_shutdown_and_wipe_sign_out_first():
    app = _read(ROOT, "android_bridge", "app.py")
    shutdown = app[app.index("    def shutdown(self) -> None:"):]
    assert shutdown.index("self._signed_in = False") < shutdown.index("self._group_calls")
    wipe = _read(ROOT, "android_bridge", "app_wipe.py")
    assert "self._signed_in = False" in wipe[wipe.index("def wipe_crypto("):][:1500]
    conn = _read(ROOT, "android_bridge", "connection.py")
    dis = conn[conn.index("    def disconnect(self) -> Dict[str, Any]:"):][:500]
    assert dis.index("signed_out()") < dis.index("self._release_transport()")


def test_u1_t6_the_engine_holds_no_previous_session_for_the_next_account(monkeypatch):
    """The residual state that matters beyond the fingerprint: sessions."""
    monkeypatch.setattr(E.otr, "_dake1_rate_limiter", E.otr.DAKE1RateLimiter())
    a, b = E._manager(), E._manager()
    first, _ = a.handle_outgoing_message("bob@example.test", "")
    E._relay(first, a, b, "alice@example.test", "bob@example.test")
    assert a.has_encrypted_session("bob@example.test")
    a.clear_all_sessions("logout")
    assert not a.sessions and not a.has_encrypted_session("bob@example.test")
