# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""The desktop app can save the same diagnostic report the phones save.

Owner, 2026-11-09: a three-way group call's third leg was the Linux desktop,
and "I don't know how to export log from it" -- there was no way to. These
pin the engine side: the op exists before and after sign-in, it is the
redacted android_bridge.report text, and the device facts name no person.
"""
import getpass
import os
import socket
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from android_bridge import report as R  # noqa: E402
from android_bridge.connection import ConnectionController  # noqa: E402
from android_bridge.trace import TRACE  # noqa: E402
from desktop_bridge import host as H  # noqa: E402


class _App:
    pass


class _Out:
    def write(self, _s):
        pass

    def flush(self):
        pass


def _host(controller=None):
    host = H.Host(_Out(), app_factory=_App, controller_factory=lambda *a: controller)
    host.app = _App()
    host.controller = controller
    return host


def test_the_report_is_there_before_sign_in():
    text = _host().call("diagnostic_report", {"app_version": "0.14.11"})
    assert text.startswith(R.HEADER)
    assert "app_version" in text and "0.14.11" in text
    assert "host" in text and "desktop" in text


def test_after_sign_in_the_controller_builds_it_with_the_desktop_facts():
    seen = {}

    class Ctl:
        def diagnostic_report(self, device):
            seen.update(device)
            return R.HEADER + "\nfrom the controller"

    text = _host(Ctl()).call("diagnostic_report", {"app_version": "9.9"})
    assert text.endswith("from the controller")
    assert seen["host"] == "desktop" and seen["app_version"] == "9.9"


def test_the_real_controller_answers_it(monkeypatch):
    # The method the host calls is the one the phones call.
    assert callable(getattr(ConnectionController, "diagnostic_report"))


def test_a_broken_controller_still_gives_a_file_not_an_exception():
    class Broken:
        def diagnostic_report(self, device):
            raise RuntimeError("secret detail must not leak")

    text = _host(Broken()).call("diagnostic_report", {})
    assert "could not be built (RuntimeError)" in text
    assert "secret detail" not in text


def test_the_device_facts_name_no_person_or_machine():
    info = H.desktop_device_info("1.0")
    flat = " ".join(info.values())
    hostname = socket.gethostname()
    if len(hostname) > 3:
        assert hostname not in flat
    try:
        user = getpass.getuser()
    except Exception:
        user = ""
    if len(user) > 3:
        assert user not in flat
    assert os.path.expanduser("~") not in flat
    assert set(info) == {"host", "os", "release", "machine", "python",
                         "core_version", "app_version", "build_id"}


# -- which commit the engine runs from (device report 2026-11-12) ----------

SHA = "155b614a899ddd09eff63dabf66242c525c96fb5"


def _git(head, refs=None, packed=None):
    import tempfile
    root = tempfile.mkdtemp()
    git = os.path.join(root, ".git")
    os.makedirs(os.path.join(git, "refs", "heads"))
    with open(os.path.join(git, "HEAD"), "w") as fh:
        fh.write(head + "\n")
    for name, value in (refs or {}).items():
        with open(os.path.join(git, name), "w") as fh:
            fh.write(value + "\n")
    if packed:
        with open(os.path.join(git, "packed-refs"), "w") as fh:
            fh.write("# pack-refs with: peeled\n" + packed)
    return root


def test_the_build_id_is_the_checked_out_commit():
    assert H.source_build_id(_git("ref: refs/heads/dev", {"refs/heads/dev": SHA})) == SHA


def test_a_packed_or_detached_head_is_read_too():
    assert H.source_build_id(_git("ref: refs/heads/dev",
                                  packed="%s refs/heads/dev\n" % SHA)) == SHA
    assert H.source_build_id(_git(SHA)) == SHA


def test_no_checkout_says_unknown_and_never_raises():
    import tempfile
    assert H.source_build_id(tempfile.mkdtemp()) == "unknown"
    assert H.source_build_id(_git("garbage")) == "unknown"


def test_the_desktop_report_names_its_build():
    text = _host().call("diagnostic_report", {"app_version": "0.15.0"})
    assert "build_id" in text


def test_identities_in_the_trace_are_labels_in_the_desktop_report():
    TRACE.record("group_call", "participant_added", "info",
                 jid="carol@example.i2p", via="join")
    text = _host().call("diagnostic_report", {})
    assert "carol@example.i2p" not in text
    assert "participant_added" in text
