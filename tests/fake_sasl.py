# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""The slice of slixmpp's `feature_mechanisms` plugin the transport configures.

Over I2P and Tor the transport restricts SASL to SCRAM (SECURITY_ISSUES X1)
and refuses to build a client it cannot restrict, so every fake client has
to carry this. The attribute names are slixmpp's own; the real plugin is
exercised in tests/test_x1_destination_pinning.py.
"""


class FakeSaslMechanisms:
    def __init__(self):
        self.use_mechs = None
        self.encrypted_plain = True
        self.unencrypted_plain = False


def sasl_plugins():
    """A `client.plugin` mapping holding only the SASL plugin."""
    return {"feature_mechanisms": FakeSaslMechanisms()}
