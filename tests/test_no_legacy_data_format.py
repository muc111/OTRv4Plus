#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""One data-message parser, not two.

`EnhancedOTRSession.decrypt_message` used to hand anything that was not a
current data frame to `_enh_dec_legacy`, a "v5" parser for a format nothing
has emitted since the data-message rewrite. It passed the frame to the
ratchet with neither the outer OTRv4 MAC check nor the instance-tag check,
and it had also stopped working -- it treated the ratchet's
`(plaintext, mkmac)` tuple as bytes -- so its only effect was a second,
weaker route into the ratchet. It is removed; this holds that.
"""

import base64
import os

import pytest

otr = pytest.importorskip("otrv4_")

from test_wipe_and_exit import _pair, _tags                           # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_the_legacy_parser_is_gone():
    src = open(os.path.join(ROOT, "otrv4+.py"), encoding="utf-8").read()
    assert "_enh_dec_legacy" not in src


def test_a_v5_shaped_frame_is_refused_without_touching_the_ratchet():
    p = _pair()
    try:
        p.alice.start_session(p.bob_jid)
        session = p.bob._engine.sessions[p.alice_jid]
        before = _tags(session.ratchet._rust)

        frame = (bytes([otr.OTRConstants.MESSAGE_TYPE_DATA])
                 + bytes(session.session_id)
                 + os.urandom(64 + 12 + 16 + 40))
        wire = "?OTRv4 " + base64.urlsafe_b64encode(frame).decode() + "."

        with pytest.raises(otr.EncryptionError):
            session.decrypt_message(wire)
        assert _tags(session.ratchet._rust) == before

        # The real path still works afterwards.
        p.alice.send_message(p.bob_jid, "still here")
        assert any(getattr(e, "body", None) == "still here"
                   for e in p.bob_sink.events)
    finally:
        for app in (p.alice, p.bob):
            app.shutdown()
