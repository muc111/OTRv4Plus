# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""The desktop app's engine process (desktop_bridge/host.py) and its
contract with the Compose GUI (desktop/).

The GUI holds no keys: it is a separate JVM process that sends commands and
renders events. These tests pin what that boundary carries -- which
operations exist, that results are plain data with no bytes, that a failure
is a code and never an exception's message, that the typed secrets are
dropped after use -- and that the desktop and Android apps read the engine
the same way.
"""
import dataclasses
import enum
import io
import json
import os
import re
import subprocess
import sys
import threading
import time

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from desktop_bridge import host as H  # noqa: E402


class Level(enum.IntEnum):
    ENCRYPTED = 1


class Phase(enum.Enum):
    VERIFIED = "verified"


@dataclasses.dataclass
class View:
    jid: str
    security: Level
    smp: Phase
    blob: bytes


class FakeApp:
    def __init__(self):
        self.seen = []

    def local_fingerprint(self):
        return "AAAA BBBB"

    def contacts(self):
        return [View("bob@x", Level.ENCRYPTED, Phase.VERIFIED, b"\x00secret")]

    def send_user_text(self, peer, body):
        self.seen.append((peer, body))
        return "encrypted"

    def smp_start(self, peer, secret, question):
        raise RuntimeError("SMP failed for secret=%s with %s" % (secret, peer))

    def shutdown(self):
        pass


class FakeController:
    def __init__(self, app, jid, server, sam_host, sam_port):
        self.args = (jid, server, sam_host, sam_port)
        self.events = []
        self.passwords = []

    def status(self):
        return {"stage": "idle", "connected": False, "jid": self.args[0]}

    def inputs_text(self):
        return "jid=%s password=present" % self.args[0]

    def connect(self, password):
        self.passwords.append(password)
        return {"ok": False, "code": "timeout", "detail": "tunnels"}

    def drain_events(self, limit=0):
        out, self.events = self.events, []
        return out


def make():
    out = io.StringIO()
    holder = {}

    def ctl(*a):
        holder["c"] = FakeController(*a)
        return holder["c"]

    host = H.Host(out, app_factory=FakeApp, controller_factory=ctl)
    host.start()
    return host, out, holder


def frames(out):
    return [json.loads(l) for l in out.getvalue().splitlines() if l.strip()]


class TestProtocol:

    def test_ready_first_with_the_fingerprint(self):
        _, out, _ = make()
        assert frames(out)[0] == {"ready": {"fingerprint": "AAAA BBBB",
                                            "python": "%d.%d" % sys.version_info[:2]}}

    def test_results_are_plain_data_and_never_bytes(self):
        host, _, _ = make()
        rows = host.call("contacts", {})
        assert rows == [{"jid": "bob@x", "security": 1, "smp": "VERIFIED", "blob": None}]
        json.dumps(rows)

    def test_unknown_operations_do_not_exist(self):
        host, _, _ = make()
        for op in ("__init__", "_transport", "load_identity", "export_keys", "eval"):
            with pytest.raises(Exception) as e:
                host.call(op, {})
            assert H.error_code(e.value) == "unknown_op"

    def test_a_failure_is_a_code_never_the_message(self):
        host, out, _ = make()
        host._run(9, "smp_start", {"peer": "bob@x", "secret": "hunter22hunter", "question": ""})
        reply = frames(out)[-1]
        assert reply == {"id": 9, "ok": False, "error": "RuntimeError"}
        assert "hunter22" not in out.getvalue()

    def test_typed_secrets_are_dropped_after_the_call(self):
        host, _, holder = make()
        host.call("prepare", {"jid": "alice@x"})
        args = {"password": "pw-123456"}
        host._run(1, "connect", args)
        assert args == {}, "the request's arguments outlive the call"
        assert holder["c"].passwords == ["pw-123456"]

    def test_connect_needs_prepare(self):
        host, _, _ = make()
        with pytest.raises(Exception) as e:
            host.call("connect", {"password": "x"})
        assert H.error_code(e.value) == "not_prepared"

    def test_connect_returns_status_with_the_outcome(self):
        host, _, _ = make()
        host.call("prepare", {"jid": "alice@x", "sam_port": 7656})
        status = host.call("connect", {"password": "x"})
        assert status["last"] == {"ok": False, "code": "timeout", "detail": "tunnels"}
        assert status["inputs_text"].startswith("jid=alice@x")

    def test_bad_lines_are_refused_not_fatal(self):
        host, out, _ = make()
        host.handle_line("not json")
        host.handle_line(json.dumps({"id": 1, "op": "contacts", "args": [1, 2]}))
        host.handle_line("x" * (H.MAX_LINE + 1))
        errors = [f["error"] for f in frames(out) if "error" in f]
        assert errors == ["bad_request", "bad_request", "line_too_long"]

    def test_events_are_pushed(self):
        host, out, holder = make()
        host.call("prepare", {"jid": "alice@x"})
        holder["c"].events = [{"type": "MessageReceived", "peer": "bob@x", "body": "hi",
                               "timestamp": 1.0}]
        t = threading.Thread(target=host.pump_events, daemon=True)
        t.start()
        deadline = time.time() + 3
        while time.time() < deadline and not any("event" in f for f in frames(out)):
            time.sleep(0.05)
        host._stop.set()
        assert {"event": {"type": "MessageReceived", "peer": "bob@x", "body": "hi",
                          "timestamp": 1.0}} in frames(out)


class TestAvatarsAndGroups:

    def test_avatar_pixels_cross_as_text_and_the_raw_bytes_do_not(self):
        host, _, _ = make()
        host.controller = type("C", (), {"avatar_pixels": lambda self, jid: {
            "id": "a1", "width": 2, "height": 1, "rgba": b"\x01\x02\x03\x04" * 2,
            "rgba_b64": "AQIDBAECAwQ="}})()
        out = host.call("avatar_pixels", {"jid": "bob@x"})
        assert out == {"id": "a1", "width": 2, "height": 1, "rgba": None, "rgba_b64": "AQIDBAECAwQ="}

    def test_the_group_and_profile_operations_are_there(self):
        for op in ("group_verify_state", "start_group_verify", "group_call_state",
                   "start_group_call", "join_group_call", "pause_group_call",
                   "hangup_group_call", "group_members", "verify_group_members",
                   "avatar_index", "avatar_pixels", "set_avatar_b64", "remove_avatar",
                   "profile_fields", "profile_get_json", "profile_set_json"):
            assert op in H.CONTROLLER_OPS, op


class TestTheOperationsAreTheEngines:

    def test_every_operation_is_a_real_method_with_those_arguments(self):
        import inspect
        from android_bridge.app import OtrApp
        from android_bridge.connection import ConnectionController
        for table, cls in ((H.CONTROLLER_OPS, ConnectionController), (H.APP_OPS, OtrApp)):
            for name, args in table.items():
                fn = getattr(cls, name)
                params = [p for p in inspect.signature(fn).parameters if p != "self"]
                assert list(args) == params[:len(args)], (cls.__name__, name)

    def test_no_operation_hands_out_key_material(self):
        for name in list(H.CONTROLLER_OPS) + list(H.APP_OPS):
            assert not re.search(r"key|seed|export|secret_bytes|dump|raw", name), name

    def test_every_op_the_gui_uses_exists(self):
        src = open(os.path.join(ROOT, "desktop", "src", "main", "kotlin", "org", "otrv4plus",
                                "desktop", "engine", "DesktopCore.kt")).read()
        used = set(re.findall(r'(?:call|controller)\("([a-z_]+)"', src))
        known = set(H.CONTROLLER_OPS) | set(H.APP_OPS) | {"prepare", "connect", "status",
                                                          "wipe", "wipe_crypto"}
        assert used and used <= known, used - known


class TestTheProcess:

    def test_stdout_carries_only_frames(self):
        pytest.importorskip("otrv4_core")
        import tempfile
        env = dict(os.environ, HOME=tempfile.mkdtemp(prefix="otr-desktop-"))
        try:
            proc = subprocess.run(
                [sys.executable, "-s", "-m", "desktop_bridge.host"], cwd=ROOT, env=env,
                input='{"id":1,"op":"local_fingerprint"}\n{"id":2,"op":"shutdown"}\n',
                capture_output=True, text=True, timeout=120)
        finally:
            import shutil
            shutil.rmtree(env["HOME"], ignore_errors=True)
        lines = [l for l in proc.stdout.splitlines() if l.strip()]
        parsed = [json.loads(l) for l in lines]           # every line is a frame
        assert "ready" in parsed[0]
        assert {"id": 2, "ok": True, "result": None} in parsed


class TestSharedWithAndroid:
    """The desktop compiles Android's plain-Kotlin files from the Android tree."""

    def _shared(self):
        gradle = open(os.path.join(ROOT, "desktop", "build.gradle.kts")).read()
        block = gradle.split("val sharedFromAndroid = listOf(", 1)[1].split(")", 1)[0]
        return re.findall(r'"([^"]+\.kt)"', block)

    def test_the_shared_files_exist_and_import_nothing_from_android(self):
        base = os.path.join(ROOT, "android", "app", "src", "main", "java")
        files = self._shared()
        assert len(files) > 40
        for rel in files:
            src = open(os.path.join(base, rel)).read()
            imports = re.findall(r"^import\s+([\w.]+)", src, re.M)
            bad = [i for i in imports if i.startswith(("android.", "androidx.", "com.chaquo"))]
            assert not bad, (rel, bad)

    def test_the_rules_the_gui_depends_on_are_shared_not_copied(self):
        files = set(self._shared())
        for rel in ("org/otrv4plus/android/bridge/OtrCore.kt",
                    "org/otrv4plus/android/chat/ChatState.kt",
                    "org/otrv4plus/android/crypto/Verification.kt",
                    "org/otrv4plus/android/crypto/CallUi.kt",
                    "org/otrv4plus/android/connection/ConnectProblem.kt",
                    "org/otrv4plus/android/theme/ThemeTokens.kt"):
            assert rel in files, rel
        desktop = os.path.join(ROOT, "desktop", "src", "main", "kotlin")
        for dirpath, _, names in os.walk(desktop):
            for n in names:
                assert n not in {os.path.basename(f) for f in files}, "copied, not shared: " + n

    def test_events_are_read_like_android(self):
        android = open(os.path.join(ROOT, "android", "app", "src", "main", "java", "org",
                                    "otrv4plus", "android", "bridge", "ChaquopyOtrCore.kt")).read()
        desktop = open(os.path.join(ROOT, "desktop", "src", "main", "kotlin", "org",
                                    "otrv4plus", "desktop", "engine", "DesktopCore.kt")).read()

        def types(src, start):
            body = src.split(start, 1)[1].split("else -> null", 1)[0]
            return set(re.findall(r'^\s*"(\w+)" ->', body, re.M))

        a = types(android, "private fun eventFrom")
        d = types(desktop, "fun eventFrom")
        assert a and a == d, (a ^ d)
