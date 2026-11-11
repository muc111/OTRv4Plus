# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""The engine's session and protocol states, its UI constants, and the
state-machine error.

Moved out of otrv4+.py unchanged (2026-11-11, so the engine can be read in
parts). The engine re-exports every name, so `otr.UIConstants` and the rest
work as before -- and now every name the engine is loaded under shares the one
set of enums.
"""
from enum import IntEnum


class SessionState(IntEnum):
    PLAINTEXT = 0
    DAKE_IN_PROGRESS = 1
    ENCRYPTED = 2
    FINISHED = 3
    FAILED = 4


class DAKEState(IntEnum):
    """DAKE protocol states - OTRv4 Spec §4.2"""

    IDLE = 0
    SENT_DAKE1 = 1
    RECEIVED_DAKE1 = 2
    SENT_DAKE2 = 3
    ESTABLISHED = 4
    FAILED = 5


class UIConstants:
    """UI Constants"""

    MAX_HISTORY_LINES = 10000
    PAGER_LINES = 20
    NOTIFICATION_THRESHOLD = 3
    PANEL_SWITCH_DELAY = 0.5
    MAX_MESSAGE_LENGTH = 4096
    MAX_PRIVMSG_LENGTH = 350
    MESSAGE_FRAGMENT_SIZE = 450
    OTR_FRAGMENT_SIZE = 450
    FRAGMENT_TIMEOUT = 120.0
    FRAGMENT_LIMIT = 50
    SMP_FRAGMENT_LIMIT = 100
    HEARTBEAT_INTERVAL = 300
    DAKE_TIMEOUT = 120.0
    REKEY_INTERVAL = 100

    class SecurityLevel(IntEnum):
        PLAINTEXT = 0
        ENCRYPTED = 1
        FINGERPRINT = 2
        SMP_VERIFIED = 3

    class SMPState(IntEnum):
        NONE = 0
        EXPECT1 = 1
        SENT1 = 2
        EXPECT2 = 3
        SENT2 = 4
        EXPECT3 = 5
        SENT3 = 6
        EXPECT4 = 7
        SUCCEEDED = 8
        FAILED = 9

    COLORS = {
        "reset": "\033[0m",
        "bold": "\033[1m",
        "dim": "\033[2m",
        "italic": "\033[3m",
        "underline": "\033[4m",
        "black": "\033[30m",
        "red": "\033[91m",
        "green": "\033[92m",
        "yellow": "\033[93m",
        "blue": "\033[94m",
        "magenta": "\033[95m",
        "cyan": "\033[96m",
        "white": "\033[97m",
        "dark_red": "\033[31m",
        "dark_green": "\033[32m",
        "dark_yellow": "\033[33m",
        "dark_blue": "\033[34m",
        "dark_magenta": "\033[35m",
        "dark_cyan": "\033[36m",
        "grey": "\033[90m",
        "orange": "\033[38;5;214m",
        "pink": "\033[38;5;213m",
        "teal": "\033[38;5;43m",
        "lime": "\033[38;5;118m",
        "gold": "\033[38;5;220m",
        "lavender": "\033[38;5;183m",
        "bg_green": "\033[42m",
        "bg_yellow": "\033[43m",
        "bg_blue": "\033[44m",
        "bg_magenta": "\033[45m",
        "bg_cyan": "\033[46m",
        "bg_red": "\033[41m",
        "dim_italic": "\033[2;3m",
        "bold_cyan": "\033[1;96m",
        "bold_green": "\033[1;92m",
        "bold_red": "\033[1;91m",
        "bold_yellow": "\033[1;93m",
    }

    SECURITY_ICONS = {
        SecurityLevel.PLAINTEXT: "🔴",
        SecurityLevel.ENCRYPTED: "🟡",
        SecurityLevel.FINGERPRINT: "🟢",
        SecurityLevel.SMP_VERIFIED: "🔵",
    }

    SECURITY_NAMES = {
        SecurityLevel.PLAINTEXT: "PLAINTEXT",
        SecurityLevel.ENCRYPTED: "ENCRYPTED",
        SecurityLevel.FINGERPRINT: "VERIFIED",
        SecurityLevel.SMP_VERIFIED: "SMP VERIFIED",
    }

    USERNAME_COLORS = [
        "bold_cyan",
        "magenta",
        "bold_green",
        "yellow",
        "orange",
        "pink",
        "teal",
        "gold",
        "lavender",
        "bold_yellow",
        "cyan",
        "dark_magenta",
    ]


def colorize(text: str, color: str) -> str:
    """Colorize text with ANSI colors"""
    return f"{UIConstants .COLORS .get (color ,'')}{text }{UIConstants .COLORS ['reset']}"


class StateMachineError(Exception):
    """State machine transition error"""

    pass
