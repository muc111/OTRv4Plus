# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""X1 in the terminal client: SCRAM only where certificates are not checked,
and the I2P server's destination pinned (docs/SECURITY_ISSUES.md X1).

The app has had both since 2026-09-28 (tests/test_x1_destination_pinning.py);
the terminal client accepted whatever the server offered, PLAIN included.
It now applies the same rule, from the same place
(android_bridge.server_pins.check_destination), which these tests run against
the app's own check so the two cannot drift.
"""
import argparse
import base64
import os
import types

import pytest

xmpp = pytest.importorskip("otrv4plus_xmpp")
slixmpp = pytest.importorskip("slixmpp")
from android_bridge import server_pins as P  # noqa: E402
from android_bridge import transport as T  # noqa: E402
import otrv4plus_address as A  # noqa: E402


@pytest.fixture
def tmp_path():
    """pytest's own tmp_path calls getpass.getuser(), which conftest's `pwd`
    stub breaks; a plain temporary directory does the same job here."""
    import pathlib
    import shutil
    import tempfile
    d = tempfile.mkdtemp()
    yield pathlib.Path(d)
    shutil.rmtree(d, ignore_errors=True)


def _dest(seed: int) -> str:
    """A destination string in I2P's base64, and its b32."""
    raw = bytes((seed + i) % 256 for i in range(391))
    text = base64.b64encode(raw).decode().replace("+", "-").replace("/", "~")
    return text


# -- SCRAM only ------------------------------------------------------------------

def test_the_terminal_and_the_app_allow_the_same_mechanisms():
    assert xmpp.SCRAM_ONLY == T.SCRAM_ONLY


def _tls_on(use_i2p, use_tor, server, insecure=False):
    client = slixmpp.ClientXMPP("alice@example.org", "pw")
    args = argparse.Namespace(insecure_tls=insecure)
    xmpp._configure_tls(client, args, server, use_i2p, use_tor)
    return client.plugin["feature_mechanisms"]


@pytest.mark.parametrize("use_i2p,use_tor,server,insecure", [
    (True, False, "otrv4plus.i2p", False),
    (False, True, "x" * 56 + ".onion", False),
    (False, False, "chat.example.org", True),
])
def test_scram_only_wherever_the_certificate_is_not_checked(use_i2p, use_tor, server, insecure):
    mech = _tls_on(use_i2p, use_tor, server, insecure)
    assert set(mech.use_mechs) == set(T.SCRAM_ONLY)
    assert mech.encrypted_plain is False and not mech.unencrypted_plain


def test_a_verified_clearnet_server_keeps_the_default():
    mech = _tls_on(False, False, "chat.example.org")
    assert set(mech.use_mechs or ()) != set(T.SCRAM_ONLY)


# -- the destination rule: the app's and the terminal's agree --------------------

def _app_verdict(host, dest, store):
    route = types.SimpleNamespace(host=host, self_authenticating=host.endswith(".b32.i2p"))
    fake = types.SimpleNamespace(_route=route, _pins=lambda: store)
    try:
        T.XmppTransport._verify_destination(fake, dest)
        return "ok"
    except P.DestinationChanged:
        return "refused"


def _shared_verdict(host, dest, store):
    try:
        P.check_destination(host, P.b32_of_destination(dest), store,
                            shipped=A.shipped_server_address(host),
                            self_authenticating=host.endswith(".b32.i2p"))
        return "ok"
    except P.DestinationChanged:
        return "refused"


def test_the_shared_rule_agrees_with_the_app_in_every_case(tmp_path):
    a, b = _dest(1), _dest(2)
    shipped_name = next(iter(A.SHIPPED_SERVERS))
    cases = [(P.b32_of_destination(a), a), (P.b32_of_destination(a), b),
             (shipped_name, a)]
    for host, dest in cases:
        s1, s2 = P.ServerPins(str(tmp_path / "1.json")), P.ServerPins(str(tmp_path / "2.json"))
        assert _app_verdict(host, dest, s1) == _shared_verdict(host, dest, s2), host
    # A name: first use, the same again, then a different destination.
    s1, s2 = P.ServerPins(str(tmp_path / "n1.json")), P.ServerPins(str(tmp_path / "n2.json"))
    for step, dest in enumerate((a, a, b)):
        got = (_app_verdict("chat.i2p", dest, s1), _shared_verdict("chat.i2p", dest, s2))
        assert got[0] == got[1], (step, got)
        if step == 0:
            s1.confirm("chat.i2p"); s2.confirm("chat.i2p")
    assert got == ("refused", "refused")


# -- the terminal client's flow --------------------------------------------------

@pytest.fixture
def store(tmp_path, monkeypatch):
    s = P.ServerPins(str(tmp_path / "pins.json"))
    monkeypatch.setattr(P, "default_store", lambda: s)
    return s


def test_first_use_pins_after_sign_in_and_a_change_is_refused(store):
    a, b = _dest(5), _dest(6)
    verify, confirm, _pins = xmpp._server_identity("chat.i2p")
    verify(a)
    assert store.pinned("chat.i2p") is None, "pinned only once sign-in succeeded"
    confirm()
    assert store.pinned("chat.i2p") == P.b32_of_destination(a)
    with pytest.raises(P.DestinationChanged) as refused:
        verify(b)
    assert refused.value.seen == P.b32_of_destination(b)


def test_the_new_address_is_trusted_only_when_typed_in_full(store, monkeypatch, capsys):
    a, b = _dest(7), _dest(8)
    verify, confirm, pins = xmpp._server_identity("chat.i2p")
    verify(a); confirm()
    with pytest.raises(P.DestinationChanged) as refused:
        verify(b)
    monkeypatch.setattr("builtins.input", lambda _p: "yes")
    assert not xmpp._ask_to_trust(refused.value, pins)
    monkeypatch.setattr("builtins.input", lambda _p: refused.value.seen)
    assert xmpp._ask_to_trust(refused.value, pins)
    verify(b)                    # approved for the next attempt
    confirm()
    assert store.pinned("chat.i2p") == P.b32_of_destination(b)
    out = capsys.readouterr().err
    assert P.b32_of_destination(a) in out and P.b32_of_destination(b) in out


def test_a_typed_b32_or_a_shipped_name_cannot_be_approved(store, monkeypatch):
    monkeypatch.setattr("builtins.input", lambda _p: pytest.fail("must not ask"))
    for name in (P.b32_of_destination(_dest(9)), next(iter(A.SHIPPED_SERVERS))):
        changed = P.DestinationChanged(name, "x.b32.i2p", "y.b32.i2p")
        assert not xmpp._ask_to_trust(changed, store)


def test_reconnects_check_the_destination_and_never_retry_a_change():
    path = os.path.join(os.path.dirname(os.path.realpath(xmpp.__file__)), "otrv4plus_xmpp_connection.py")
    src = open(path, encoding="utf-8").read()
    block = src[src.index("_tunnels.start_i2p_sam_forwarder("):][:1500]
    assert 'verify=getattr(self, "_server_check", None)' in block
    assert "DestinationChanged" in block and "return" in block


# -- a pins file that will not open (X1 residual 5, closed) ---------------------

def _unreadable_store(monkeypatch, content="{not json"):
    import tempfile
    path = os.path.join(tempfile.mkdtemp(prefix="otrv4plus-x1-term-"), "pins.json")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)
    s = P.ServerPins(path)
    monkeypatch.setattr(P, "default_store", lambda: s)
    return s, path


def test_the_terminal_applies_the_same_rule_via_check_destination(monkeypatch):
    store, path = _unreadable_store(monkeypatch)
    a = _dest(11)
    with pytest.raises(P.PinsUnreadable) as refused:
        P.check_destination("chat.i2p", P.b32_of_destination(a), store,
                            shipped=None, self_authenticating=False)
    assert refused.value.path == path
    # A typed b32 and a shipped name never consult the pins, as in the app.
    b32 = P.b32_of_destination(a)
    assert P.check_destination(b32, b32, store, shipped=None,
                               self_authenticating=True) == "b32 address"
    with pytest.raises(P.PinsUnreadable):
        xmpp._server_identity("chat.i2p")
    verify, _confirm, _pins = xmpp._server_identity(b32)
    verify(a)


def test_the_terminal_refuses_an_unreadable_pins_file_before_the_router_is_asked(
        monkeypatch, capsys):
    import asyncio
    import otrv4plus_egress
    _store, path = _unreadable_store(monkeypatch, '{"chat.i2p": {"b32": 5}}')
    started = []

    async def _forwarder(*a, **kw):
        started.append(a)
        raise AssertionError("the router was asked")

    monkeypatch.setattr(xmpp._tunnels, "start_i2p_sam_forwarder", _forwarder)
    monkeypatch.setattr(otrv4plus_egress, "enter", lambda *a, **kw: None)
    client = types.SimpleNamespace(loop=asyncio.new_event_loop(),
                                   connect=lambda *a: pytest.fail("connected"))
    args = argparse.Namespace(port=5222, sam_host="127.0.0.1", sam_port=7656)
    try:
        with pytest.raises(SystemExit):
            xmpp._open_connection(client, args, "chat.i2p", True, False)
    finally:
        client.loop.close()
    assert started == [], "the SAM forwarder was started"
    err = capsys.readouterr().err
    assert path in err and "Nothing was sent" in err
    assert open(path, encoding="utf-8").read() == '{"chat.i2p": {"b32": 5}}'


def test_a_terminal_reconnect_stops_at_an_unreadable_pins_file(monkeypatch):
    path = os.path.join(os.path.dirname(os.path.realpath(xmpp.__file__)),
                        "otrv4plus_xmpp_connection.py")
    src = open(path, encoding="utf-8").read()
    block = src[src.index('getattr(check, "preflight"'):]
    assert block.index("PinsUnreadable") < block.index("_tunnels.start_i2p_sam_forwarder(")
    assert "return" in block[:block.index("_tunnels.start_i2p_sam_forwarder(")]
    # ...and the preflight it calls is the client's own, refusing once the
    # file will not open (made unreadable after start, then read again).
    import tempfile
    pins_path = os.path.join(tempfile.mkdtemp(prefix="otrv4plus-x1-term-"), "pins.json")
    store = P.ServerPins(pins_path)
    monkeypatch.setattr(P, "default_store", lambda: store)
    verify, _c, _p = xmpp._server_identity("chat.i2p")
    verify.preflight()
    with open(pins_path, "w", encoding="utf-8") as fh:
        fh.write("{not json")
    store._load()                       # what a fresh process would read
    with pytest.raises(P.PinsUnreadable):
        verify.preflight()


def test_a_missing_pins_file_is_a_first_run_for_the_terminal(monkeypatch):
    import tempfile
    s = P.ServerPins(os.path.join(tempfile.mkdtemp(prefix="otrv4plus-x1-term-"), "pins.json"))
    monkeypatch.setattr(P, "default_store", lambda: s)
    a = _dest(12)
    verify, confirm, _pins = xmpp._server_identity("chat.i2p")
    verify(a)
    confirm()
    assert s.pinned("chat.i2p") == P.b32_of_destination(a)
