# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""The Qubes packaging scripts and formula (qubes/), checked without Qubes.

build-deb.sh refuses a core that carries the raw-key test API; its list must
be the release guard's, or the package gate checks names that do not exist
(it did, once: three invented names that no build ever had).
"""
import ast
import os
import re
import subprocess

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
QUBES = os.path.join(ROOT, "qubes")


def _read(*parts):
    with open(os.path.join(ROOT, *parts), encoding="utf-8") as fh:
        return fh.read()


def _literal(src, name):
    m = re.search(r"^%s = (\(.*?\)|\{.*?\})$" % name, src, re.S | re.M)
    assert m, "%s not found" % name
    return ast.literal_eval(m.group(1))


def test_the_package_gate_uses_the_release_guards_list():
    deb = _read("qubes", "packaging", "build-deb.sh")
    guard = _read("tests", "test_release_guard.py")
    assert _literal(deb, "RAW_KEY_FUNCTIONS") == _literal(guard, "RAW_KEY_MODULE_FUNCTIONS")
    assert _literal(deb, "RAW_KEY_METHODS") == _literal(guard, "RAW_KEY_CLASS_METHODS")


@pytest.mark.parametrize("script", ["build-deb.sh", "build-core.sh", "fetch-sources.sh"])
def test_scripts_parse(script):
    subprocess.run(["bash", "-n", os.path.join(QUBES, "packaging", script)], check=True)


def test_no_dns_resolver_is_shipped():
    deb = _read("qubes", "packaging", "build-deb.sh")
    for name in ("aiodns", "pycares", "cffi"):
        assert '"%s"' % name in deb, "the forbidden-package check lost " + name
    for lock in ("lock-cp313.sha256", "lock-cp312.sha256"):
        text = _read("qubes", "packaging", lock).lower()
        assert not any(n in text for n in ("aiodns", "pycares", "cffi", "pycparser")), lock


def test_policy_allows_only_the_sam_bridge():
    policy = _read("qubes", "salt", "otrv4plus", "files", "30-otrv4plus.policy")
    rules = [l.split() for l in policy.splitlines() if l.strip() and not l.startswith("#")]
    allows = [r for r in rules if r[4] == "allow"]
    assert allows == [
        ["qubes.ConnectTCP", "+7656", "otr-chat", "sys-i2p", "allow"],
        ["otrv4plus.SamUdp", "*", "otr-chat", "sys-i2p", "allow"],
    ]
    assert ["qubes.ClipboardPaste", "*", "otr-chat", "@anyvm", "deny"] in rules
    assert ["qubes.ClipboardPaste", "*", "@anyvm", "otr-chat", "deny"] in rules
    # The broad ConnectTCP deny comes after the one allow (first match wins).
    i_allow = rules.index(["qubes.ConnectTCP", "+7656", "otr-chat", "sys-i2p", "allow"])
    i_deny = rules.index(["qubes.ConnectTCP", "*", "otr-chat", "@anyvm", "deny"])
    assert i_allow < i_deny


def test_the_chat_qube_has_no_network():
    dom0 = _read("qubes", "salt", "otrv4plus", "dom0.sls")
    chat = dom0.split("\notr-chat:\n", 1)[1].split("\n\n", 1)[0]
    assert '- netvm: ""' in chat
    assert "service.otrv4plus-sam-proxy" in chat


def test_sam_is_on_loopback_only_in_sys_i2p():
    conf = _read("qubes", "salt", "otrv4plus", "files", "i2pd.conf")
    sections, cur = {}, ""
    for line in conf.splitlines():
        line = line.strip()
        if line.startswith("["):
            cur = line.strip("[]")
        elif "=" in line and not line.startswith("#"):
            k, v = (x.strip() for x in line.split("=", 1))
            sections.setdefault(cur, {})[k] = v
    assert sections["sam"] == {"enabled": "true", "address": "127.0.0.1",
                               "port": "7656", "portudp": "7655"}
    for off in ("http", "httpproxy", "socksproxy", "bob", "i2cp", "i2pcontrol", "upnp"):
        assert sections[off]["enabled"] == "false", off
