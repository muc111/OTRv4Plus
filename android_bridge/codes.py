# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Every failure code the bridge can report, and what each one means.

A code is the name of one place that failed. It is what the app shows when
it has no sentence (FailureText's fallback), what the debug log records, and
what to grep for: `grep -rn '"call_tunnel"' android_bridge client` lands on
the line that produced it.

Every ErrorOccurred and every BridgeError is noted here as it is created, so
the debug log has each failure with its time and peer label even when no
screen was attached, and the diagnostic report opens with a tally of what
failed and how often. `tests/test_failure_codes_registered.py` fails when the
bridge can produce a code this table does not list.
"""
from __future__ import annotations

import threading
import time
from typing import Dict, List, Tuple

from .trace import TRACE

__all__ = ["CODES", "describe", "note", "tally", "render_tally", "reset"]

#: code -> (component, what failed). The component is the debug-log column.
CODES: Dict[str, Tuple[str, str]] = {
    # -- one-to-one calls (android_bridge/voice.py) --------------------------
    "call_not_placed": ("call", "the call could not be started (no reason recorded)"),
    "call_not_answered": ("call", "answering the incoming call failed"),
    "call_not_ended": ("call", "hanging up failed"),
    "call_signal_failed": ("call", "a call signal from the peer could not be handled"),
    "call_unavailable": ("call", "voice is not available on this device or build"),
    "call_in_call": ("call", "a call with this contact is already running"),
    "call_no_session": ("call", "no encrypted session with this contact"),
    "call_unverified": ("call", "the contact is not verified (SMP) yet"),
    "call_rate_limited": ("call", "too many call attempts in a short time"),
    "call_key_exchange": ("call", "the call's key exchange did not complete"),
    "call_tunnel": ("call", "the I2P voice tunnel could not be opened"),
    # -- group calls (group_call.py, group_call_bridge.py, groups.py) --------
    "call_audio_unavailable": ("group_call", "no audio backend for the group call"),
    "call_full": ("group_call", "the group call has no free place"),
    "call_rekey_failed": ("group_call", "the group call's key change failed"),
    "call_control_failed": ("group_call", "a group call control message failed"),
    "group_too_large": ("group_call", "the room is too large for a group call"),
    # -- OTR sessions (app.py) -----------------------------------------------
    "connect_failed": ("otr", "the engine could not be started for this account"),
    "engine_required": ("otr", "the call needs the engine, which is not loaded"),
    "session_start_failed": ("otr", "the encrypted session could not be started"),
    "dake_generate_failed": ("otr", "the key exchange message could not be made"),
    "identity_unavailable": ("identity", "this account's stored identity would not open; it is not replaced (F3)"),
    "dake_send_failed": ("otr", "the key exchange message could not be sent"),
    "pq_downgrade": ("otr", "handshake refused: the contact's identity used ML-DSA before and now did not (A2)"),
    "pq_v2_required": ("otr", "handshake refused: the contact's app does not run protocol v2 (A1, A2 fixed)"),
    "pq_key_changed": ("otr", "handshake refused: the contact's identity now uses a different ML-DSA key (A2)"),
    "encrypt_failed": ("otr", "the message could not be encrypted"),
    "decrypt_failed": ("otr", "an incoming message could not be decrypted"),
    "not_encrypted": ("otr", "the conversation is not encrypted"),
    "no_transport": ("otr", "not connected to the server"),
    "protocol_send_failed": ("otr", "a handshake message could not be sent"),
    "wiped": ("otr", "the app was wiped; nothing more is accepted"),
    "otrv4plus_unknown": ("otr", "the contact has not been seen online yet"),
    "otrv4plus_offline": ("otr", "the contact is offline"),
    "otrv4plus_checking": ("otr", "still asking the contact's device what it supports"),
    "otrv4plus_unavailable": ("otr", "the contact's client does not speak OTRv4Plus"),
    "waiting_for_contact": ("otr", "1:1 message held: a contact request was sent, the session starts when they accept"),
    "plaintext_refused": ("otr", "1:1 message held: the contact's client offers no OTRv4+, and nothing is ever sent unencrypted"),
    # -- verification (app_smp.py) -------------------------------------------
    "smp_not_encrypted": ("smp", "verification needs an encrypted session first"),
    "smp_not_produced": ("smp", "the engine produced no verification message"),
    "smp_send_failed": ("smp", "the verification message could not be sent"),
    "smp_respond_failed": ("smp", "answering the verification failed"),
    "smp_resume_unsupported": ("smp", "this engine cannot resume a held verification"),
    "smp_resume_failed": ("smp", "resuming the held verification failed"),
    "smp_held_request_gone": ("smp", "the verification request expired before the answer"),
    "smp_not_requested": ("smp", "there is no verification request to answer"),
    "smp_abort_unsupported": ("smp", "this engine cannot cancel a verification"),
    "smp_cooldown": ("smp", "verification is cooling down after a failure"),
    "smp_attempts_exhausted": ("smp", "too many failed verification attempts"),
    "smp_already_verified": ("smp", "the contact is already verified"),
    "smp_in_progress": ("smp", "a verification is already running"),
    "smp_start_failed": ("smp", "the verification could not be started"),
    "verify_control_failed": ("smp", "a group verification control message failed"),
    # -- rooms and secure groups (app_rooms.py, groups.py) -------------------
    "room_not_encryptable": ("room", "rooms cannot have a one-to-one encrypted session"),
    "room_not_verifiable": ("room", "rooms cannot be verified with SMP"),
    "room_not_persistent": ("room", "the server did not make the room persistent"),
    "room_message_rejected": ("room", "the server rejected a room message"),
    "room_plaintext_refused": ("room", "a plaintext message in a secure room was refused"),
    "group_invite_failed": ("group", "the group invitation could not be sent"),
    "group_removal_unconfirmed": ("group", "Delete removed everyone but the room did not confirm it in time; nothing deleted yet"),
    "group_joining": ("group", "still joining the group; try again shortly"),
    "group_keys_missing": ("group", "no keys for this group on this device"),
    "group_send_failed": ("group", "a group message could not be sent"),
    "group_rekey_failed": ("group", "changing the group's keys failed"),
    "group_remove_failed": ("group", "removing a member failed"),
    "group_signal_unencrypted": ("group", "an unencrypted group signal was refused"),
    "group_welcome_send_failed": ("group", "the welcome for a new member could not be sent"),
    "group_welcome_unconfirmed": ("group", "a new member never confirmed the welcome"),
    "groups_state_too_large": ("group", "the saved group state is too large to keep"),
    "groups_state_unreadable": ("group", "the saved group state could not be read"),
    "epoch_listener_failed": ("group", "an internal group listener raised"),
    # -- files (files.py, group_files.py, app_files.py) ----------------------
    "file_signal_failed": ("file", "a file transfer signal could not be handled"),
    "file_control_failed": ("file", "a group file control message failed"),
    "group_file_unverified": ("file", "a group file came from an unverified member"),
    "open_failed": ("file", "the received file could not be opened"),
}

#: A second note of the same code inside this window is the same failure seen
#: twice (an ErrorOccurred and the BridgeError raised right after it).
_SAME_FAILURE_S = 1.0

_lock = threading.Lock()
_seen: Dict[str, List[float]] = {}          # code -> [count, first, last]
_last: Tuple[str, float] = ("", 0.0)


def describe(code: str) -> str:
    """`component: meaning` for *code*, or a note that it is unregistered."""
    entry = CODES.get(code)
    return "%s: %s" % entry if entry else "unregistered code"


def note(code: str, peer: str = "") -> None:
    """Write one failure to the debug log and count it. Never raises."""
    global _last
    try:
        code = str(code)
        now = time.time()
        with _lock:
            if _last[0] == code and now - _last[1] < _SAME_FAILURE_S:
                return
            _last = (code, now)
            row = _seen.setdefault(code, [0, now, now])
            row[0] += 1
            row[2] = now
        component, meaning = CODES.get(code, ("failure", "unregistered code"))
        fields = {"code": code, "meaning": meaning}
        if peer:
            fields["jid"] = peer
        TRACE.record(component, "failed", "warning", **fields)
    except Exception:
        return


def tally() -> List[Tuple[str, int, float, float]]:
    """(code, count, first, last) for every code seen, most frequent first."""
    with _lock:
        rows = [(c, int(r[0]), r[1], r[2]) for c, r in _seen.items()]
    return sorted(rows, key=lambda r: (-r[1], -r[3]))


def render_tally() -> str:
    rows = tally()
    if not rows:
        return "  none since the app started"
    stamp = lambda t: time.strftime("%H:%M:%S", time.localtime(t))  # noqa: E731
    return "\n".join("  %-26s x%-3d first %s  last %s  (%s)"
                     % (code, n, stamp(first), stamp(last), describe(code))
                     for code, n, first, last in rows)


def reset() -> None:
    """Forget the tally. For tests, and for a wipe."""
    global _last
    with _lock:
        _seen.clear()
        _last = ("", 0.0)
