# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""The service's "start the I2P router?" agrees with the bridge's route.

Two places decide: `RouterChoice.needsI2p` (Kotlin, whether to start or find a
router before connecting) and `android_bridge.route.classify` (Python, where
the connection actually goes). If they disagree, a clearnet or Tor account
starts a router it does not need, or an I2P account connects with none.
Every case in RouterChoiceTest is run here against the bridge.
"""
import os
import re

import otrv4plus_address as address
from android_bridge import route

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KT_TEST = os.path.join(ROOT, "android", "app", "src", "test", "java", "org", "otrv4plus",
                       "android", "connection", "RouterChoiceTest.kt")
CASE = re.compile(r'assert(True|False)\(RouterChoice\.needsI2p\("([^"]*)", "([^"]*)"\)\)')


def _cases():
    return [(kind == "True", jid, server)
            for kind, jid, server in CASE.findall(open(KT_TEST, encoding="utf-8").read())]


def test_the_kotlin_cases_are_found():
    assert len(_cases()) >= 10


def test_every_kotlin_case_matches_the_bridges_route():
    checked = 0
    for needs_i2p, jid, server in _cases():
        target = server or address.jid_domain(jid.split("/")[0])
        try:
            kind = route.classify(target).kind
        except route.RouteError:
            continue        # never reaches the network; nothing to agree on
        assert (kind == route.I2P_SAM) == needs_i2p, (jid, server, kind)
        checked += 1
    assert checked >= 7


def test_clearnet_and_tor_accounts_route_without_i2p():
    assert route.classify("jabber.de").kind == route.CLEARNET_TLS
    assert route.classify("chat.example.org:5223").kind == route.CLEARNET_TLS
    onion = "a" * 56 + ".onion"
    assert route.classify(onion).kind == route.TOR
    assert route.classify(onion).verify_certificate is False
    assert route.classify("jabber.de").verify_certificate is True
