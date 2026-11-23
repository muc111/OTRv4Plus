# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""The terminal clients' settings (OTRConfig): the server and how to reach
it (TLS, SASL, Tor), NickServ, where keys, trust and logs are stored and
whether they persist, and the protocol's timeouts and intervals. Moved out
of otrv4+.py, which re-exports it."""
from dataclasses import dataclass, field
from typing import Optional, Tuple


@dataclass
class OTRConfig:
    """Mutable configuration object"""

    trust_db_path: Optional[str] = None
    smp_secrets_path: Optional[str] = None
    key_storage_path: Optional[str] = None
    log_file_path: Optional[str] = None
    test_mode: bool = False
    i2p_proxy: Tuple[str, int] = ("127.0.0.1", 4447)
    i2p_sam: Tuple[str, int] = ("127.0.0.1", 7656)
    tor_proxy: Tuple[str, int] = ("127.0.0.1", 9050)
    server: str = "irc.postman.i2p"
    port: int = 0
    use_tls: bool = False
    sasl_user: Optional[str] = None
    # repr=False: a dataclass repr prints every field, and this one
    # ends up in debug output and exception text.
    sasl_pass: Optional[str] = field(default=None, repr=False)
    channel: str = "#otr"
    log_level: str = "INFO"
    dake_timeout: float = 120.0
    fragment_timeout: float = 120.0
    heartbeat_interval: int = 300
    rekey_interval: int = 100
    nickserv_login: bool = False
    nickserv_register: bool = False
    nickserv_nick: Optional[str] = None
    nickserv_pass: Optional[str] = field(default=None, repr=False)

    # -- Identity and trust persistence -----------------------------------
    #
    # Both default OFF, and that default is the IRC behaviour: a fresh Ed448
    # identity every process and no trust record that outlives it.  That is
    # deliberate (ROADMAP Phase 5.3g) and not a limitation to be fixed -- an
    # IRC nick is ephemeral, so pinning a fingerprint to one means pinning it
    # to nothing.
    #
    # XMPP turns both on.  A JID is a durable name, so an identity that changes
    # under it is a fact worth noticing, and TOFU is only meaningful once the
    # local identity stops changing too.
    #
    # These are separate switches because they fail independently: identity
    # persistence can be unavailable (no writable state directory) while trust
    # pinning is still wanted for the session, and a caller that wants neither
    # should not have to opt out of both by accident.
    persist_identity: bool = False
    persist_trust: bool = False
    #: Refuse a peer whose signed profile does not list both v2 capabilities
    #: (PQ_RATCHET_VERSION, PQ_AUTH_VERSION): no fallback to the v1 ratchet
    #: (A1) or v1 authentication (A2). Off only for interop tests.
    require_pq_v2: bool = True

    #: Sealed long-term identity record.  Only read when persist_identity.
    identity_path: Optional[str] = None
    #: Device-local key protecting `identity_path`.  Only read when
    #: persist_identity.  See TermuxFileDekProvider for what this does and,
    #: more importantly, what it does not do.
    identity_dek_path: Optional[str] = None
    #: Key file sealing the trust pins (P1).  Only read when persist_trust.
    #: Set, the pins are kept sealed beside it (`android_bridge.account_trust`,
    #: F3's sealing path), and a plaintext `trust_db_path` from before is moved
    #: in once and removed.  Unset, they are the plaintext `trust_db_path`.
    trust_dek_path: Optional[str] = None
