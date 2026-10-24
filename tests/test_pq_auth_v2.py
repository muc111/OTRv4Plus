# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Protocol v2: post-quantum authentication both ways, pinned (A2).

docs/SECURITY_ISSUES.md A2: only the initiator signed with ML-DSA, with a key
made for that one handshake, so the signature proved nothing about who sent
it, and an attacker able to forge Ed448 could simply leave it out. Now:

  * each identity has ONE long-term ML-DSA key (sealed beside the Ed448
    identity when the identity persists);
  * with both profiles listing PQ_AUTH_VERSION the responder signs DAKE2 and
    the initiator DAKE3, both mandatory (Rust: `dake::pq_auth_tests`);
  * a peer's key is pinned on its first v2 handshake, and a later handshake
    under the same Ed448 identity that drops it or changes it is REFUSED --
    the Ed448 fingerprint the user would check matches in exactly that attack.
"""
import os
import shutil
import tempfile

import pytest

import test_smp_end_to_end as E

otr = E.otr
A, B = "alice@example.test", "bob@example.test"

@pytest.fixture(autouse=True)
def _own_rate_limiter(monkeypatch):
    monkeypatch.setattr(otr, "_dake1_rate_limiter", otr.DAKE1RateLimiter())


def _handshake(a, b):
    a.end_session(B)
    b.end_session(A)
    first, _ = a.handle_outgoing_message(B, "")
    E._relay(first, a, b, A, B)
    return a.has_encrypted_session(B) and b.has_encrypted_session(A)


def _pin(manager, peer):
    return (manager.trust_db._db.get(peer) or {}).get("pq")


def _key(manager):
    import hashlib
    return hashlib.sha3_256(manager.client_profile.mldsa_identity.pub_bytes).hexdigest()


@pytest.fixture
def pinned():
    a, b = E._manager(), E._manager()
    assert _handshake(a, b), "a first v2 handshake"
    return a, b


def test_both_ends_pin_the_others_long_term_ml_dsa_key(pinned):
    a, b = pinned
    assert _pin(a, B)["mldsa"] == _key(b)
    assert _pin(b, A)["mldsa"] == _key(a)


def test_the_same_key_every_handshake_so_the_pin_holds(pinned):
    a, b = pinned
    for _ in range(2):
        assert _handshake(a, b)
        assert _pin(a, B)["mldsa"] == _key(b)


@pytest.mark.parametrize("old", [[4], [4, 0x50]], ids=["v1", "rc158"])
@pytest.mark.parametrize("who", ["initiator", "responder"])
def test_by_default_a_peer_without_both_v2_capabilities_is_refused(old, who):
    a, b = E._manager(), E._manager()
    (a if who == "initiator" else b).client_profile.versions = list(old)
    assert not _handshake(a, b), "no fallback to v1"
    refuser, peer = (b, A) if who == "initiator" else (a, B)
    assert refuser.take_pq_refusal(peer) == "pq_v2_required"


def test_dropping_post_quantum_authentication_is_refused(pinned):
    # Even where the version policy is relaxed, the pin still holds.
    a, b = pinned
    a.config.require_pq_v2 = b.config.require_pq_v2 = False
    b.client_profile.versions = [otr.OTRConstants.PROTOCOL_VERSION,
                                 otr.OTRConstants.PQ_RATCHET_VERSION]
    assert not _handshake(a, b), "same Ed448 identity, no ML-DSA: the A2 attack"
    assert a.take_pq_refusal(B) == "pq_downgrade"
    assert a.take_pq_refusal(B) is None, "reported once"


def test_a_different_ml_dsa_key_is_refused(pinned):
    a, b = pinned
    b.client_profile.mldsa_identity = otr.MLDSA87Auth()
    assert not _handshake(a, b)
    assert a.take_pq_refusal(B) == "pq_key_changed"


def test_resetting_trust_for_the_contact_clears_the_pin(pinned):
    a, b = pinned
    b.client_profile.mldsa_identity = otr.MLDSA87Auth()
    assert not _handshake(a, b)
    a.take_pq_refusal(B)
    a.trust_db.remove_trust(B)
    assert _handshake(a, b), "a deliberate reset accepts the new key"
    assert _pin(a, B)["mldsa"] == _key(b)


def test_with_the_policy_off_a_v1_peer_is_never_pinned_and_still_talks():
    a, b = E._manager(), E._manager()
    a.config.require_pq_v2 = b.config.require_pq_v2 = False
    b.client_profile.versions = [otr.OTRConstants.PROTOCOL_VERSION]
    for _ in range(2):
        assert _handshake(a, b), "a v1 peer's per-handshake keys pin nothing"
    assert _pin(a, B) is None and _pin(b, A) is None


def test_the_fingerprint_pin_and_the_ml_dsa_pin_live_together(pinned):
    a, b = pinned
    fp = b.client_profile.get_fingerprint()
    assert a.trust_db.check_or_pin(B, fp) is False   # first contact for the UI layer
    a.trust_db.add_trust(B, fp)
    entry = a.trust_db._db[B]
    assert entry["fingerprint"] == fp and entry["trusted"] and entry["pq"]["mldsa"] == _key(b)


# -- the long-term key is persistent --------------------------------------------

@pytest.fixture
def store():
    d = tempfile.mkdtemp()
    yield os.path.join(d, "identity.bin"), os.path.join(d, "identity.dek")
    shutil.rmtree(d, ignore_errors=True)


def test_the_ml_dsa_identity_is_created_once_and_reloaded(store):
    from otrv4plus_identity import load_or_create_mldsa
    first = load_or_create_mldsa(*store)
    again = load_or_create_mldsa(*store)
    assert bytes(first.public_bytes) == bytes(again.public_bytes)
    assert os.stat(store[0] + ".mldsa").st_mode & 0o077 == 0, "0600"


def test_a_damaged_record_fails_closed_and_is_not_replaced(store):
    from otrv4plus_identity import load_or_create_mldsa, IdentityUnavailable
    load_or_create_mldsa(*store)
    path = store[0] + ".mldsa"
    blob = bytearray(open(path, "rb").read())
    blob[50] ^= 1
    open(path, "wb").write(bytes(blob))
    with pytest.raises(IdentityUnavailable):
        load_or_create_mldsa(*store)
    assert open(path, "rb").read() == bytes(blob), "left for the user to decide"


def test_a_persistent_identity_brings_its_ml_dsa_key_across_restarts(store):
    def manager():
        config = otr.OTRConfig(test_mode=True)
        config.persist_identity = True
        config.identity_path, config.identity_dek_path = store
        config.trust_db_path = store[0] + ".trust.json"
        return otr.EnhancedSessionManager(config=config)
    first, second = manager(), manager()
    assert (first.client_profile.mldsa_identity.pub_bytes
            == second.client_profile.mldsa_identity.pub_bytes)
    assert (first.client_profile.get_fingerprint()
            == second.client_profile.get_fingerprint())


@pytest.mark.parametrize("code", ["pq_downgrade", "pq_key_changed", "pq_v2_required"])
def test_the_app_is_told_why_with_a_registered_code(code):
    import types
    from android_bridge import codes
    from android_bridge.app import OtrApp
    app = OtrApp.__new__(OtrApp)
    seen = []
    app._emit = seen.append
    app._engine = types.SimpleNamespace(take_pq_refusal=lambda peer: code)
    app._report_pq_refusal(B)
    assert [(e.peer, e.code) for e in seen] == [(B, code)]
    assert code in codes.CODES


def test_resetting_trust_from_the_app_clears_the_pin(pinned):
    from android_bridge.app import OtrApp
    a, b = pinned
    app = OtrApp.__new__(OtrApp)
    app._engine = a
    app.canonical_peer = lambda p: p
    app._safe = lambda fn, default=None: fn()
    assert app.reset_trust(B)
    assert _pin(a, B) is None
