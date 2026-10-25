# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Wipe & Exit: deleting the account on the server if asked, then every
secret and every record on the device.

A mixin of OtrApp (app.py). docs/ANDROID_WIPE_AND_EXIT.md is the design."""
from __future__ import annotations

import os
from typing import Any, Dict, Optional

from otrv4plus_mode import OtrMode

from .events import ConnectionState


class WipeMixin:
    """Wipe & Exit. Mixed into OtrApp."""

    def delete_server_account(self, timeout: Optional[float] = None) -> str:
        """Wipe & Exit's opt-in last word to the server: delete this account
        (XEP-0077). Runs on the live, already-authenticated session, AFTER the
        keys are destroyed in Rust and BEFORE the transport closes. Returns
        the transport's outcome ("deleted", "unconfirmed", "refused",
        "offline") or "unsupported". Never raises; never blocks for long."""
        transport = self._transport
        if transport is None:
            return "offline"
        remove = getattr(transport, "delete_account", None)
        if remove is None:
            return "unsupported"
        try:
            return str(remove(timeout))
        except Exception:
            return "unconfirmed"

    def wipe(self, delete_account: bool = False) -> Dict[str, Any]:
        """Wipe & Exit, Python side. Idempotent; the app is spent afterwards.

        [delete_account]: the user also asked for the account to be deleted
        on the server. Done after the Rust keys are gone (stage B) and before
        the transport closes; reported as `server_account`, and never a
        reason for the rest of the wipe to wait or stop.

        NOT `shutdown` with more steps. `shutdown` is a logout: sessions end,
        the facade stays usable for the next account, and pinned fingerprints
        survive. This destroys, and refuses to be used again.

        THE ORDER, and why each step is where it is:

          1. Refuse. `_wiped` is set first, so from here no event reaches the
             UI (`_emit`) and no call or transfer bridge can be rebuilt
             (`calls`, `files`, and the methods on them). The engine refuses
             in its own right once step 4 runs.
          2. Calls. They hold a microphone, a SAM session and media keys, and
             their END rides the OTR session step 4 destroys -- so they go
             while it still exists. `CallBridge.shutdown` ends each call, then
             force-closes whatever is left, which zeroizes the key schedule;
             then it drains, stops and CLOSES its event loop.
          3. Transfers. Each FileKey holder is told to zeroize and each
             partial file is closed and unlinked, before the session is gone.
          4. The engine, on the transport's loop thread, where inbound frames
             are processed, so the wipe cannot interleave with one.
             `EnhancedSessionManager.wipe` zeroizes every ratchet, SMP state,
             vault, handshake and the identity handles in Rust, then refuses
             all further use.
          5. The transport. `close`, not `disconnect`: the XMPP stream, the
             I2P tunnel and the loop thread all go, and the object is spent.
          6. What this facade remembered: presence, last activity, the OTR
             mode, call states.
          7. Disk. Everything the Python side persists -- see
             `android_bridge.wipe` for exactly what that is on Android, and
             what an overwrite on flash does and does not achieve.

        Returns counts for the caller's report. Never raises: a step that
        fails is recorded and the rest still run, because a wipe that stops
        at the first problem is worse than one that reports it.
        """
        with self._wipe_lock:
            already = self._wiped
            self._wiped = True
        report: Dict[str, Any] = {"already_wiped": already, "errors": []}
        # A note being recorded: the microphone off and the PCM overwritten.
        try:
            self.voice_note_cancel()
            self.voice_note_play_stop()
        except Exception:
            report["errors"].append("voice_note")

        # STAGE B FIRST: every secret destroyed in Rust before anything that
        # can wait on the network. See `wipe_crypto`.
        crypto = self.wipe_crypto()
        report["errors"].extend(crypto.get("errors", []))
        report.update({k: v for k, v in crypto.items()
                       if k not in ("errors", "already_wiped")})

        # STAGE C: stop the subsystems. The calls' keys are already gone, so
        # no END is attempted -- it could not be encrypted -- and the peer's
        # side times out; what remains is releasing audio, SAM and the loop.
        calls, self._calls_bridge = self._calls_bridge, None
        if calls is not None:
            try:
                calls.shutdown(graceful=False)
            except TypeError:
                calls.shutdown()
            except Exception:
                report["errors"].append("calls")

        # The server, if asked: the account and what the server keeps for it.
        report["server_account"] = (self.delete_server_account() if delete_account
                                    else "not_requested")

        transport = self._transport
        self._transport = None
        if transport is not None:
            closer = getattr(transport, "close", None) or transport.disconnect
            try:
                closer()
            except Exception:
                report["errors"].append("transport")
        self._connection = ConnectionState.DISCONNECTED

        self._presence.forget_all()
        self._last_activity.clear()
        self._mode = OtrMode()
        self._call_states.clear()
        # Room memberships (addresses: who this account talks to in groups)
        # and the diagnostics trace (aliased, but still a record of activity).
        try:
            self.forget_rooms()
        except Exception:
            report["errors"].append("rooms")
        try:
            from .trace import TRACE as _trace
            _trace.clear()
            from . import codes as _codes
            _codes.reset()
        except Exception:
            report["errors"].append("trace")
        try:
            from . import server_pins as _pins
            _pins.default_store().forget()
        except Exception:
            report["errors"].append("server_pins")

        from . import wipe as _disk
        destroyed = failed = 0
        for root in _disk.python_state_roots():
            d, f = _disk.destroy_tree(root)
            destroyed += d
            failed += f
        report["files_destroyed"] = destroyed
        report["files_unlinked_only"] = failed
        self._sink = None
        return report

    def wipe_crypto(self) -> Dict[str, Any]:
        """Wipe & Exit, STAGE B: destroy every secret in Rust. Local only.

        Runs before anything that can wait on a network timeout, so that the
        cryptographic state is gone first whatever happens after:

          * each call's key schedule, key exchange and media ciphers,
            force-closed (`CallBridge.destroy_keys`) -- no END is sent;
          * each transfer's FileKey, zeroized, and partial files unlinked;
          * the engine (`EnhancedSessionManager.wipe`): every ratchet, DAKE,
            SMP state and vault, and the identity and prekey handles -- on
            the transport's loop thread, so it cannot interleave with an
            inbound frame.

        Sets `_wiped` first, so nothing can recreate state meanwhile.
        Idempotent; never raises. `wipe()` calls it before its own teardown.
        """
        with self._wipe_lock:
            already = getattr(self, "_crypto_wiped", False)
            self._crypto_wiped = True
            self._wiped = True
        report: Dict[str, Any] = {"already_wiped": already, "errors": []}
        if already:
            return report
        # Lines waiting to be sent are plaintext the user typed: gone too.
        for box in getattr(self, "_outbox", {}).values():
            box.clear()
        getattr(self, "_outbox", {}).clear()
        getattr(self, "_markable", {}).clear()
        # The archive cursor (android_bridge.sync): an opaque id, but it is
        # this account's, and Wipe & Exit leaves nothing of the account.
        try:
            import otrv4plus_sync as _sync
            from .sync import CURSOR_PATH
            _sync.ArchiveCursor(os.path.expanduser(CURSOR_PATH)).forget()
        except Exception as exc:
            report["errors"].append("sync_cursor:%s" % type(exc).__name__)
        getattr(self, "_invite_after_otr", {}).clear()
        getattr(self, "_message_requested", set()).clear()

        calls = self._calls_bridge
        if calls is not None:
            destroy = getattr(calls, "destroy_keys", None)
            try:
                if destroy is not None:
                    destroy()
                else:
                    calls.shutdown()
                    self._calls_bridge = None
            except Exception:
                report["errors"].append("call_keys")
        files, self._files_bridge = self._files_bridge, None
        if files is not None:
            try:
                files.shutdown()
            except Exception:
                report["errors"].append("transfers")
        group_files, self._group_files = self._group_files, None
        if group_files is not None:
            try:
                group_files.close()
            except Exception:
                report["errors"].append("group_transfers")
        # Every MLS group secret, pending commit and the signing key, in
        # Rust, and the sealed state file. Constructed here if it was never
        # used, so a state file from a previous run is removed too.
        try:
            self.groups.wipe()
        except Exception:
            report["errors"].append("groups")

        engine_wipe = getattr(self._engine, "wipe", None)

        def _wipe_engine():
            if engine_wipe is not None:
                return engine_wipe("wipe and exit")
            self._engine.clear_all_sessions("wipe and exit")
            return {}

        runner = getattr(self._transport, "run_on_loop_thread", None)
        try:
            counts = runner(_wipe_engine) if runner is not None else _wipe_engine()
        except Exception:
            # The loop could not run it (stopped mid-teardown, timed out).
            # Here, then: an output made on that thread may leak rather than
            # zeroize, which is worse than the right thread and far better
            # than leaving every session alive.
            report["errors"].append("engine_off_thread")
            try:
                counts = _wipe_engine()
            except Exception:
                report["errors"].append("engine")
                counts = {}
        report.update({k: v for k, v in (counts or {}).items()
                       if k != "already_wiped"})
        return report
