# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""The terminal clients' log and protocol trace.

* `NullLogger` -- accepts every call and does nothing (tests, and code
  that runs before a logger exists).
* `OTRLogger`  -- the client's log, quiet unless debugging.
* `OTRTracer`  -- a per-peer record of protocol steps, for --debug.

Moved out of otrv4+.py, which re-exports all three.
"""
import json
import logging
import logging.handlers
import os
import threading
from typing import Any, Dict, Optional

import otrv4plus_debug as _debug
from otrv4plus_config import OTRConfig
from otrv4plus_states import colorize
from otrv4plus_tty import colorize_username


class NullLogger:
    """Logger that does nothing - for testing"""

    def __init__(self):
        pass

    def security_event(self, event: str, session_id: str, peer: str, details: dict):
        pass

    def network_message(self, direction: str, peer: str, msg_type: str, length: int):
        pass

    def ui_interaction(self, action: str, panel: str, user_input: str):
        pass

    def session_transition(self, old_state: str, new_state: str, peer: str, session_id: str):
        pass

    def info(self, msg: str):
        pass

    def warning(self, msg: str):
        pass

    def error(self, msg: str):
        pass

    def debug(self, msg: str):
        pass


class OTRLogger:
    """Structured logging framework"""

    def __init__(self, config: Optional[OTRConfig] = None):
        self.config = config or OTRConfig()
        self._setup_loggers()

    def _setup_loggers(self):
        """Setup structured loggers"""
        log_dir = os.path.dirname(self.config.log_file_path or "~/.otrv4/logs/otrv4.log")
        log_dir = os.path.expanduser(log_dir)
        os.makedirs(log_dir, exist_ok=True)
        try:
            os.chmod(log_dir, 0o700)
        except Exception:
            pass

        log_file = self.config.log_file_path or os.path.join(log_dir, "otrv4plus.log")
        if not os.path.exists(log_file):
            try:
                with open(log_file, "a"):
                    pass
                os.chmod(log_file, 0o600)
            except Exception:
                pass

        handler = logging.handlers.RotatingFileHandler(
            log_file, maxBytes=10 * 1024 * 1024, backupCount=5
        )

        formatter = logging.Formatter("%(asctime)s | %(levelname)-8s | %(name)-15s | %(message)s")
        handler.setFormatter(formatter)

        self.security_logger = logging.getLogger("otrv4.security")
        self.network_logger = logging.getLogger("otrv4.network")
        self.ui_logger = logging.getLogger("otrv4.ui")
        self.session_logger = logging.getLogger("otrv4.session")

        for logger in [
            self.security_logger,
            self.network_logger,
            self.ui_logger,
            self.session_logger,
        ]:
            logger.addHandler(handler)
            logger.setLevel(getattr(logging, self.config.log_level.upper()))
            logger.propagate = False

    def security_event(self, event: str, session_id: str, peer: str, details: dict):
        """Log security events"""
        self.security_logger.info(
            f"EVENT={event } | SESSION={session_id } | PEER={peer } | {json .dumps (details )}"
        )

    def network_message(self, direction: str, peer: str, msg_type: str, length: int):
        """Log network I/O"""
        self.network_logger.debug(
            f"DIRECTION={direction } | PEER={peer } | TYPE={msg_type } | LENGTH={length }"
        )

    def ui_interaction(self, action: str, panel: str, user_input: str):
        """Log UI interactions (excluding secrets)"""
        self.ui_logger.info(f"ACTION={action } | PANEL={panel } | INPUT_LENGTH={len (user_input )}")

    def session_transition(self, old_state: str, new_state: str, peer: str, session_id: str):
        """Log session state transitions"""
        self.session_logger.info(
            f"TRANSITION={old_state }→{new_state } | PEER={peer } | SESSION={session_id }"
        )

    def info(self, msg: str):
        """Log info message"""
        self.security_logger.info(msg)

    def warning(self, msg: str):
        """Log warning message"""
        self.security_logger.warning(msg)

    def error(self, msg: str):
        """Log error message"""
        self.security_logger.error(msg)

    def debug(self, msg: str):
        """Log debug message"""
        self.security_logger.debug(msg)


class OTRTracer:
    """
    Unified tracing subsystem for OTRv4 state monitoring.

    Traces are NEVER printed directly to stdout.  The client registers a
    callback (set_emit_callback) which routes each trace line to the debug
    panel.  This keeps all OTR internals out of the channel/system tabs.
    """

    def __init__(self, enabled: bool = True, logger: Optional[OTRLogger] = None):
        self.enabled = enabled or _debug.FLAGS.debug
        self.logger = logger
        self.peer_states: Dict[str, Dict[str, Any]] = {}
        self.lock = threading.RLock()
        self._emit_cb = None

    def set_emit_callback(self, cb) -> None:
        """Register the client's debug-panel emit function."""
        self._emit_cb = cb

    def trace(
        self,
        peer: str,
        category: str,
        old_state: Any,
        new_state: Any,
        reason: Optional[str] = None,
        details: Optional[Dict] = None,
    ):
        """Record a state transition. Output goes ONLY to debug panel, never stdout."""
        if not self.enabled:
            return

        with self.lock:
            if peer not in self.peer_states:
                self.peer_states[peer] = {}
            self.peer_states[peer][category] = new_state

            old_str = (
                str(old_state)
                .replace("State.", "")
                .replace("SMPState.", "")
                .replace("DAKEState.", "")
            )
            new_str = (
                str(new_state)
                .replace("State.", "")
                .replace("SMPState.", "")
                .replace("DAKEState.", "")
            )

            msg = f"[OTR:{peer }] {category }: {old_str } → {new_str }"
            if reason:
                msg += f" | {reason }"

            if self.logger:
                self.logger.session_transition(old_str, new_str, peer, category)

            color = (
                "green"
                if "ESTABLISHED" in new_str or "ENCRYPTED" in new_str
                else (
                    "red"
                    if "FAILED" in new_str
                    else "yellow" if "SENT" in new_str or "RECEIVED" in new_str else "cyan"
                )
            )
            colored_msg = colorize(msg, color)

            if self._emit_cb:
                self._emit_cb(colored_msg)
                if details and _debug.FLAGS.debug:
                    for k, v in details.items():
                        if k not in ("secret", "key", "nonce", "private", "password"):
                            self._emit_cb(f"  {k }: {v }")

    def get_peer_state(self, peer: str, category: Optional[str] = None) -> Any:
        """Get current state for peer"""
        with self.lock:
            if peer not in self.peer_states:
                return None
            if category:
                return self.peer_states[peer].get(category)
            return self.peer_states[peer].copy()

    def reset_peer(self, peer: str):
        """Reset all tracing for a peer"""
        with self.lock:
            if peer in self.peer_states:
                del self.peer_states[peer]
                self.trace(peer, "TRACER", "ACTIVE", "RESET", "peer reset")

    def is_session_encrypted(self, peer: str) -> bool:
        """Check if session is encrypted"""
        with self.lock:
            state = self.get_peer_state(peer, "SESSION")
            return state == "ENCRYPTED"

    def is_dake_complete(self, peer: str) -> bool:
        """Check if DAKE completed successfully"""
        with self.lock:
            state = self.get_peer_state(peer, "DAKE")
            return state == "ESTABLISHED"

    def format_state_report(self, peer: str) -> str:
        """Format comprehensive state report for peer"""
        with self.lock:
            if peer not in self.peer_states:
                return f"No state tracked for {peer }"

            report = []
            report.append(f"OTR State Report for {colorize_username (peer )}:")
            for category, state in sorted(self.peer_states[peer].items()):
                state_str = (
                    str(state)
                    .replace("State.", "")
                    .replace("SMPState.", "")
                    .replace("DAKEState.", "")
                )
                report.append(f"  {category :12} : {state_str }")

            return "\n".join(report)
