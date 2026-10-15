# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""The engine, as a separate process the desktop GUI talks to.

    python3 -I -m desktop_bridge.host        (cwd / PYTHONPATH: the app dir)

On Android the Compose UI and the engine share one process: Chaquopy embeds
Python, and Kotlin calls `android_bridge` directly. On the desktop they do
not, deliberately:

  GUI (Kotlin/JVM, Compose)  --JSON lines-->  this process (Python)  -->  otrv4_core (Rust)
        no keys, no crypto        stdin/stdout      orchestration          every key, every
        shows what it is told                                              cipher, every proof

The JVM never holds a key, a ratchet or a session secret: it sends commands
("send this text to bob", "start SMP with this secret") and renders events.
The secrets it does touch are the ones a person types -- the account
password and an SMP secret -- and they pass straight through to here.

THE SAME ENGINE AS THE APP. Every operation below is a method of
`android_bridge.app.OtrApp` or `android_bridge.connection.ConnectionController`,
the objects the Android app drives through Chaquopy; the result shapes are
the ones `ChaquopyOtrCore.kt` reads. Nothing here decides anything about
security -- it forwards and serialises.

Protocol, one JSON object per line:

  -> {"id": 7, "op": "send_user_text", "args": {"peer": "bob@x", "body": "hi"}}
  <- {"id": 7, "ok": true, "result": "sent"}
  <- {"id": 8, "ok": false, "error": "not_connected"}
  <- {"event": {"type": "MessageReceived", "peer": ..., "body": ..., ...}}
  <- {"ready": {...}}                 once, at start (or {"fatal": code})

Only operations in the tables below exist; anything else is "unknown_op".
Errors carry a CODE, never an exception's message: a message can embed the
plaintext or the peer data it was handling (the Android bridge drops them for
the same reason).

stdout is the protocol channel and nothing else may write to it: the real
stdout is duplicated for the protocol and fd 1 is pointed at stderr before
the engine is imported, so a stray print() -- the engine has many -- cannot
corrupt a frame.
"""
from __future__ import annotations

import dataclasses
import enum
import json
import os
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable, Dict, Optional

#: Controller operations: name -> argument names, in call order.
CONTROLLER_OPS: Dict[str, tuple] = {
    "register": ("password",),
    "cancel": (),
    "disconnect": (),
    "destination_change": (),
    "approve_server_destination": ("b32",),
    "add_contact": ("jid", "name"),
    "remove_contact": ("jid",),
    "answer_subscription": ("jid", "approve"),
    "subscription_policy": (),
    "discover_services": (),
    "discover_rooms": ("service",),
    "join_room": ("room", "nick"),
    "create_room": ("room", "nick"),
    "leave_room": ("room", "nick"),
    "block_contact": ("jid", "report"),
    "unblock_contact": ("jid",),
    "blocked_contacts": (),
    "room_occupants": ("room",),
    "joined_rooms": (),
    "create_secure_group": ("room", "password"),
    "secure_groups": (),
    "group_members": ("room",),
    "group_invites": (),
    "invite_to_group": ("room", "peer"),
    "accept_group_invite": ("room",),
    "decline_group_invite": ("room",),
    "leave_secure_group": ("room",),
    "start_group_verify": ("room", "passphrase"),
    "group_verify_state": ("room",),
    "start_group_call": ("room",),
    "join_group_call": ("room",),
    "pause_group_call": (),
    "hangup_group_call": (),
    "group_call_state": ("room",),
    "set_group_call_auto_join": ("allowed",),
    "verify_group_members": ("room",),
    "remove_group_member": ("room", "member"),
    "delete_secure_group": ("room",),
    # Avatars arrive as PIXELS (RGBA, base64 text) decoded by the bounded
    # decoder in android_bridge/avatar.py: no image decoder in the GUI ever
    # reads a file a peer sent. Our own picture goes the other way as PNG
    # the GUI made from the user's own file, checked like anybody's.
    "avatar_index": (),
    "avatar_pixels": ("jid",),
    "set_avatar_b64": ("text",),
    "remove_avatar": (),
    "profile_fields": (),
    "profile_set_json": ("text",),
    "welcome_directory": (),
    "discover_online_users": (),
    "profile_get_json": ("jid",),
    "test_server": (),
    "probe": (),
}

#: OtrApp operations: name -> argument names.
APP_OPS: Dict[str, tuple] = {
    "contacts": (),
    "local_fingerprint": (),
    "security_state": ("peer",),
    "smp_state": ("peer",),
    "smp_progress": ("peer",),
    "smp_secret_required": ("peer",),
    "security_details": ("peer",),
    "otr_capability": ("peer",),
    "ensure_otr": ("peer",),
    "handshake_status": ("peer",),
    "start_session": ("peer",),
    "send_user_text": ("peer", "body", "message_id", "reply_to"),
    "send_action": ("peer", "action", "target_id", "body", "emojis", "message_id"),
    "mark_displayed": ("peer",),
    "set_chat_state": ("peer", "state"),
    "set_privacy": ("chat_states", "read_markers"),
    "set_client_active": ("active",),
    "sync_status": (),
    "smp_start": ("peer", "secret", "question"),
    "smp_respond": ("peer", "secret"),
    "smp_abort": ("peer",),
    "call_state": ("peer",),
    "call_gate": ("peer",),
    "call_duration_seconds": ("peer",),
    "start_call": ("peer",),
    "answer_call": ("peer",),
    "end_call": ("peer",),
    "voice_unavailable_reason": (),
    "send_file": ("peer", "path", "strip_metadata"),
    "inspect_file": ("path",),
    "voice_note_modes": (),
    "voice_note_start": (),
    "voice_note_status": (),
    "voice_note_stop": ("mode", "directory"),
    "voice_note_cancel": (),
    "voice_note_play": ("path",),
    "voice_note_play_stop": (),
    "voice_note_discard": ("path",),
    "accept_file": ("transfer_id",),
    "decline_file": ("transfer_id",),
    "cancel_file": ("transfer_id",),
    "transfers": (),
    "received_file_dir": (),
    "save_received": ("path", "destination"),
}

#: How often queued engine events are pushed to the GUI.
EVENT_INTERVAL = 0.25
#: Requests that block on I2P (minutes, for a cold tunnel) run in parallel.
WORKERS = 6
#: A request line longer than this is refused unread: no legitimate command
#: is near it, and the limit bounds what a confused GUI can make us allocate.
MAX_LINE = 1 << 20


def plain(value: Any, depth: int = 0) -> Any:
    """`value` as JSON: dataclasses and mappings to objects, IntEnum to its
    number (SecurityState is a level), other enums to their name. Bytes are
    never sent: nothing the GUI renders is binary, and key material is."""
    if depth > 12:
        return None
    if value is None or isinstance(value, (bool, int, float, str)):
        if isinstance(value, enum.IntEnum):
            return int(value)
        return value
    if isinstance(value, enum.Enum):
        return value.name
    if isinstance(value, (bytes, bytearray, memoryview)):
        return None
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {f.name: plain(getattr(value, f.name), depth + 1)
                for f in dataclasses.fields(value)}
    if isinstance(value, dict):
        return {str(k): plain(v, depth + 1) for k, v in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [plain(v, depth + 1) for v in value]
    return type(value).__name__


def error_code(exc: BaseException) -> str:
    """A stable code for a failure, never its message."""
    code = getattr(exc, "code", None)
    if isinstance(code, str) and code and code.replace("_", "").isalnum():
        return code
    return type(exc).__name__ or "bridge_error"


class Host:
    """One engine, one GUI. Not thread-hostile: requests run on a pool, as
    Kotlin's Dispatchers.IO runs them on Android."""

    def __init__(self, out, app_factory: Optional[Callable[[], Any]] = None,
                 controller_factory: Optional[Callable[..., Any]] = None):
        self._out = out
        self._out_lock = threading.Lock()
        self._app_factory = app_factory or _real_app
        self._controller_factory = controller_factory or _real_controller
        self.app: Any = None
        self.controller: Any = None
        self._stop = threading.Event()
        self._pool = ThreadPoolExecutor(max_workers=WORKERS,
                                        thread_name_prefix="otr-host")

    # -- output ----------------------------------------------------------------

    def send(self, obj: Dict[str, Any]) -> None:
        line = json.dumps(obj, separators=(",", ":"), ensure_ascii=False)
        with self._out_lock:
            self._out.write(line + "\n")
            self._out.flush()

    # -- operations --------------------------------------------------------------

    def start(self) -> None:
        self.app = self._app_factory()
        self.send({"ready": {"fingerprint": self._safe(self.app.local_fingerprint),
                             "python": "%d.%d" % sys.version_info[:2]}})

    def _status(self, last: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        ctl = self.controller
        if ctl is None:
            return {"stage": "idle", "connected": False}
        status = plain(ctl.status())
        if last is not None:
            status["last"] = plain(last)
        try:
            status["inputs_text"] = str(ctl.inputs_text())
        except Exception:
            status["inputs_text"] = ""
        return status

    def call(self, op: str, args: Dict[str, Any]) -> Any:
        if op == "prepare":
            self.controller = self._controller_factory(
                self.app, str(args.get("jid", "")), str(args.get("server", "")),
                str(args.get("sam_host", "")), int(args.get("sam_port", 0) or 0))
            return self._status()
        if op == "status":
            return self._status()
        if op == "connect":
            if self.controller is None:
                raise _Coded("not_prepared")
            return self._status(self.controller.connect(str(args.get("password", ""))))
        if op in ("wipe", "wipe_crypto"):
            target = self.controller if self.controller is not None else self.app
            if op == "wipe":
                result = plain(target.wipe(delete_account=bool(args.get("delete_account"))))
            else:
                result = plain(target.wipe_crypto())
            if op == "wipe":
                self._stop.set()
            return result
        if op in CONTROLLER_OPS:
            if self.controller is None:
                raise _Coded("not_prepared")
            return plain(getattr(self.controller, op)(
                *[args[a] for a in CONTROLLER_OPS[op] if a in args]))
        if op in APP_OPS:
            return plain(getattr(self.app, op)(
                *[args[a] for a in APP_OPS[op] if a in args]))
        raise _Coded("unknown_op")

    def _run(self, rid: Any, op: str, args: Dict[str, Any]) -> None:
        try:
            result = self.call(op, args)
        except BaseException as exc:          # noqa: BLE001 -- reported as a code
            self.send({"id": rid, "ok": False, "error": error_code(exc)})
        else:
            self.send({"id": rid, "ok": True, "result": result})
        finally:
            args.clear()                       # the password, an SMP secret

    def handle_line(self, line: str) -> None:
        if len(line) > MAX_LINE:
            self.send({"id": None, "ok": False, "error": "line_too_long"})
            return
        try:
            req = json.loads(line)
            rid, op = req.get("id"), str(req["op"])
            args = req.get("args") or {}
            if not isinstance(args, dict):
                raise ValueError
        except Exception:
            self.send({"id": None, "ok": False, "error": "bad_request"})
            return
        if op == "shutdown":
            self._stop.set()
            self.send({"id": rid, "ok": True, "result": None})
            return
        self._pool.submit(self._run, rid, op, args)

    def pump_events(self) -> None:
        while not self._stop.wait(EVENT_INTERVAL):
            ctl = self.controller
            if ctl is None:
                continue
            try:
                events = ctl.drain_events(0)
            except Exception:
                continue
            for ev in events or ():
                self.send({"event": plain(ev)})

    def serve(self, stdin) -> None:
        pump = threading.Thread(target=self.pump_events, name="otr-events", daemon=True)
        pump.start()
        for line in stdin:
            if self._stop.is_set():
                break
            line = line.strip()
            if line:
                self.handle_line(line)
            if self._stop.is_set():
                break
        self._stop.set()
        self._pool.shutdown(wait=False, cancel_futures=True)
        try:
            if self.app is not None:
                self.app.shutdown()
        except Exception:
            pass

    @staticmethod
    def _safe(fn):
        try:
            return fn()
        except Exception:
            return ""


class _Coded(RuntimeError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _real_app():
    from android_bridge import bootstrap
    bootstrap.ensure_runtime()
    otr = bootstrap.load_orchestration()
    from android_bridge.app import OtrApp
    return OtrApp(otr.EnhancedSessionManager(otr.OTRConfig()))


def _real_controller(app, jid, server, sam_host, sam_port):
    from android_bridge.connection import controller_for
    return controller_for(app, jid, server, sam_host, sam_port)


def main() -> int:
    # The protocol gets its own copy of stdout; fd 1 becomes stderr, so
    # nothing the engine prints can land in a frame.
    proto = os.fdopen(os.dup(1), "w", encoding="utf-8", buffering=1)
    os.dup2(2, 1)
    sys.stdout = sys.stderr
    host = Host(proto)
    try:
        host.start()
    except BaseException as exc:              # noqa: BLE001
        host.send({"fatal": error_code(exc)})
        return 1
    host.serve(sys.stdin)
    return 0


if __name__ == "__main__":
    sys.exit(main())
