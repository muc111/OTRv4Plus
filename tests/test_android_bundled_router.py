# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""The I2P router built into the APK (connection/BundledRouter.kt).

The Kotlin rules are executed by RouterChoiceTest in CI. These check the
parts that live outside Kotlin: the Python side follows the bridge's SAM
datagram port, the build pins every source, the APK inspection looks for
the router, and the licences of what it links are declared.
"""
from __future__ import annotations

import os
import re
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import otrv4plus_voice as voice  # noqa: E402
from android_bridge.app import OtrApp  # noqa: E402
from android_bridge.connection import controller_for  # noqa: E402


def _read(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as f:
        return f.read()


@pytest.fixture
def clean_env(monkeypatch):
    monkeypatch.delenv("OTRV4PLUS_SAM_UDP_PORT", raising=False)
    yield
    os.environ.pop("OTRV4PLUS_SAM_UDP_PORT", None)


class TestDatagramPort:
    def test_the_built_in_router_gets_its_datagram_port(self, clean_env):
        app = OtrApp.__new__(OtrApp)
        controller_for(app, "alice@otrv4plus.i2p", "", "", 17656)
        assert voice.sam_udp_port() == 17655

    def test_a_router_on_the_phone_keeps_the_default(self, clean_env):
        app = OtrApp.__new__(OtrApp)
        controller_for(app, "alice@otrv4plus.i2p", "", "", 17656)
        controller_for(app, "alice@otrv4plus.i2p", "", "", 0)
        assert voice.sam_udp_port() == voice.SAM_UDP_PORT == 7655


class TestBuild:
    SCRIPT = ".github/scripts/build-i2pd-android.sh"

    def test_every_source_is_pinned_to_a_commit(self):
        s = _read(self.SCRIPT)
        for name in ("I2PD", "OPENSSL", "BOOST"):
            assert re.search(r"^%s_TAG=\S+$" % name, s, re.M), name
            assert re.search(r"^%s_COMMIT=[0-9a-f]{40}$" % name, s, re.M), name
        # And the hash is actually compared, not just written down.
        assert '"$got" != "$commit"' in s

    def test_the_inspected_version_is_the_built_one(self):
        tag = re.search(r"^I2PD_TAG=(\S+)$", _read(self.SCRIPT), re.M).group(1)
        assert 'I2PD_VERSION = b"%s"' % tag in _read(".github/scripts/inspect_apk.py")

    def test_the_router_links_nothing_android_lacks(self):
        s = _read(self.SCRIPT)
        assert "no-shared" in s and "link=static" in s and "c++_static" in s
        assert "which Android does not provide" in s

    def test_the_apk_jobs_wait_for_the_router(self):
        wf = _read(".github/workflows/android.yml")
        assert "build-i2pd-android.sh" in wf
        for job in ("apk:", "apk-release:"):
            block = wf.split("\n  %s" % job, 1)[1].split("\n  # ----", 1)[0]
            assert "i2pd" in block.split("steps:", 1)[0], job
            assert "pattern: i2pd-*" in block, job


class TestConfig:
    KT = "android/app/src/main/java/org/otrv4plus/android/connection/RouterChoice.kt"

    def test_only_sam_listens_and_only_on_loopback(self):
        conf = _read(self.KT)
        assert "address = 127.0.0.1" in conf
        for section in ("http", "httpproxy", "socksproxy", "bob", "i2cp",
                        "i2pcontrol", "upnp"):
            assert re.search(r"\|\[%s\]\n\s*\|enabled = false" % section, conf), section

    def test_limited_transit_never_floodfill(self):
        conf = _read(self.KT)
        assert "|floodfill = false" in conf
        assert "|bandwidth = L" in conf
        assert "|transittunnels = 50" in conf
        assert "|verify = true" in conf


class TestLicences:
    def test_notice_and_licensing_name_the_router(self):
        notice = _read("NOTICE")
        for name in ("i2pd", "OpenSSL", "Boost"):
            assert name in notice, name
        assert "i2pd" in _read("LICENSING.md")
