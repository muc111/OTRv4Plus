# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Protocol v2: the post-quantum ratchet through two real sessions (A1).

docs/SECURITY_ISSUES.md A1: the v1 ratchet rotated an ML-KEM brace key that no
message key depended on, so the post-quantum exchange protected nothing. v2
(SPEC §5.2) folds each new ML-KEM secret into the root step, carries the KEM
item on every message of a chain, and binds it into the AEAD. The Rust tests
(`ratchet::pq_ratchet`) cover the ratchet itself; these drive it the way a
message travels, through the managers, and pin the negotiation:

  * v2 only when BOTH signed profiles list PQ_RATCHET_VERSION;
  * a peer that does not list it gets v1, unchanged, and still talks;
  * a v2 item that is altered or stripped in transit is refused, and the
    session survives it.
"""
import base64

import pytest

import test_smp_end_to_end as E

otr = E.otr
A, B = "alice@example.test", "bob@example.test"


def _pair(monkeypatch, alice_versions=None, bob_versions=None, rekey=3):
    # A short interval so the first DH step, and the first ML-KEM exchange,
    # come within a few messages rather than a hundred.
    monkeypatch.setattr(otr.OTRConstants, "REKEY_INTERVAL", rekey)
    a, b = E._manager(), E._manager()
    if alice_versions is not None:
        a.client_profile.versions = alice_versions
    if bob_versions is not None:
        b.client_profile.versions = bob_versions
    first, _ = a.handle_outgoing_message(B, "")
    E._relay(first, a, b, A, B)
    assert a.has_encrypted_session(B) and b.has_encrypted_session(A)
    return a, b, a.get_session(B), b.get_session(A)


def _talk(a, b, rounds):
    for i in range(rounds):
        m, _ = a.handle_outgoing_message(B, f"a{i}")
        assert b.handle_incoming_message(A, m) == f"a{i}".encode()
        m, _ = b.handle_outgoing_message(A, f"b{i}")
        assert a.handle_incoming_message(B, m) == f"b{i}".encode()


def test_this_build_advertises_v2_in_its_signed_profile():
    p = otr.ClientProfile()
    assert p.versions == [otr.OTRConstants.PROTOCOL_VERSION,
                          otr.OTRConstants.PQ_RATCHET_VERSION]
    back = otr.ClientProfile.decode(p.encode())
    assert otr.OTRConstants.PQ_RATCHET_VERSION in back.versions


def test_two_v2_peers_rotate_a_fresh_post_quantum_secret_and_agree(monkeypatch):
    a, b, sa, sb = _pair(monkeypatch)
    assert sa.ratchet.pq and sb.ratchet.pq
    seen = set()
    for _ in range(8):
        _talk(a, b, 1)
        assert sa.ratchet._brace_key == sb.ratchet._brace_key
        seen.add(sa.ratchet._brace_key)
    assert len(seen) >= 6, "a new ML-KEM secret nearly every round trip"


@pytest.mark.parametrize("who", ["alice", "bob"])
def test_a_peer_without_v2_gets_v1_and_still_talks(monkeypatch, who):
    v1 = [otr.OTRConstants.PROTOCOL_VERSION]
    kw = {"alice_versions": v1} if who == "alice" else {"bob_versions": v1}
    a, b, sa, sb = _pair(monkeypatch, **kw)
    assert not sa.ratchet.pq and not sb.ratchet.pq, "both ends must agree on v1"
    _talk(a, b, 6)


def _frame(text):
    body = text[len("?OTRv4 "):-1]
    return otr.OTRv4DataMessage.decode(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))


def _wire(dmsg):
    return "?OTRv4 " + base64.urlsafe_b64encode(dmsg.encode()).decode().rstrip("=") + "."


def _refused(manager, peer, text):
    try:
        out = manager.handle_incoming_message(peer, text)
    except Exception:
        return True
    return out is None or not out.startswith(b"a")


def test_an_altered_or_stripped_item_is_refused_and_the_session_survives(monkeypatch):
    a, b, sa, sb = _pair(monkeypatch)
    _talk(a, b, 3)                      # past the first step: items now flow
    m, _ = a.handle_outgoing_message(B, "a-x")
    d = _frame(m)
    assert d.kem_ek is not None or d.kem_ct is not None, "a v2 chain carries an item"
    field = "kem_ek" if d.kem_ek is not None else "kem_ct"
    altered = bytearray(getattr(d, field))
    altered[11] ^= 0x20
    setattr(d, field, bytes(altered))
    assert _refused(b, A, _wire(d)), "the item is bound to the message"
    stripped = _frame(m)
    setattr(stripped, field, None)
    assert _refused(b, A, _wire(stripped)), "and cannot be removed"
    assert b.handle_incoming_message(A, m) == b"a-x", "the genuine message still decrypts"
    _talk(a, b, 3)
    assert sa.ratchet._brace_key == sb.ratchet._brace_key


def test_v2_never_uses_the_v1_brace_path(monkeypatch):
    _a, _b, sa, _sb = _pair(monkeypatch)
    with pytest.raises(ValueError, match="v2"):
        sa.ratchet._rust.brace_encapsulate(bytes(1568))
