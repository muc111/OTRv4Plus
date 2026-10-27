# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""The terminal client creates accounts too (`--register`), the apps' way.

Owner, 2026-10-27: "should be able to from all apps". The Android and
desktop apps create an account through `ConnectionController.register`; the
terminal had no way at all. `--register` runs that same controller -- the
route decided from the server name (or `--tor` / `--no-i2p`), the egress
rule, X1's destination check and SCRAM-only, the same codes and sentences --
and then signs in with the password just set.
"""
from __future__ import annotations

import argparse

import pytest

xmpp = pytest.importorskip("otrv4plus_xmpp")
from android_bridge import connection as C  # noqa: E402


def _args(**kw):
    base = dict(jid="newuser@example.com", server=None, port=5222,
                sam_host="127.0.0.1", sam_port=7656, socks_host="127.0.0.1",
                socks_port=9050, tor=False, no_i2p=False, insecure_tls=False)
    base.update(kw)
    return argparse.Namespace(**base)


class _Transport:
    """Stands in for XmppTransport: records the profile, answers [answer]."""
    seen = []
    answer = ("ok", "The account was created.")

    def __init__(self, profile, password, **kw):
        type(self).seen.append((profile, password))

    def register_account(self):
        return type(self).answer

    def close(self):
        pass


@pytest.fixture
def transport(monkeypatch):
    _Transport.seen = []
    _Transport.answer = ("ok", "The account was created.")
    monkeypatch.setattr(C, "_default_transport_factory", lambda: _Transport)
    return _Transport


def test_the_terminal_has_a_register_option():
    args = xmpp._parser().parse_args(["--jid", "a@example.com", "--register"])
    assert args.register is True
    assert xmpp._parser().parse_args(["--jid", "a@example.com"]).register is False


def test_register_goes_through_the_apps_controller(transport, capsys):
    xmpp._register_account(_args(no_i2p=True), "correct horse battery staple 9")
    (profile, password), = transport.seen
    assert profile.jid == "newuser@example.com"
    assert profile.transport == "clearnet_tls"
    assert password == "correct horse battery staple 9"
    assert "account created" in capsys.readouterr().out


def test_a_refused_registration_exits_with_its_sentence_and_code(transport):
    transport.answer = ("conflict", "That username is already taken.")
    with pytest.raises(SystemExit) as stop:
        xmpp._register_account(_args(no_i2p=True), "pw-pw-pw-pw-pw")
    assert "already taken" in str(stop.value) and "(conflict)" in str(stop.value)
    assert "pw-pw" not in str(stop.value)


def test_routes_follow_the_terminal_flags(transport):
    xmpp._register_account(_args(no_i2p=True), "pw")
    xmpp._register_account(_args(jid="u@example.com", port=5223, no_i2p=True), "pw")
    kinds = [p.transport for p, _ in transport.seen]
    assert kinds == ["clearnet_tls", "clearnet_tls"]
    assert transport.seen[1][0].server == "example.com:5223"


def test_insecure_tls_is_refused_before_anything_is_sent(transport):
    with pytest.raises(SystemExit) as stop:
        xmpp._register_account(_args(no_i2p=True, insecure_tls=True), "pw")
    assert "insecure-tls" in str(stop.value)
    assert transport.seen == []


def test_main_asks_twice_and_registers_before_signing_in():
    src = open(xmpp.__file__, encoding="utf-8").read()
    main = src[src.index("def main():"):]
    reg = main.index("_register_account(args, password)")
    assert main.index('getpass.getpass("Same password again: ")') < reg
    assert reg < main.index("OTRv4PlusXMPP(args.jid, password")
