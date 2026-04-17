#!/usr/bin/env python3
"""
Regression tests for v10.4 security fixes (7 CVEs addressed).
Updated for Rust-backed implementation.
Run with: pytest test_v10_4_security_fixes.py -v
"""
import struct, secrets, time, pytest
from unittest.mock import MagicMock
import otrv4plus
import otrv4_ as _otr


def test_secure_wipe_bytes_is_safe():
    wipe = getattr(otrv4plus, "_secure_wipe_bytes", None)
    if wipe is None:
        try:
            import otr4_crypto_ext
            wipe = getattr(otr4_crypto_ext, "_secure_wipe_bytes", None)
        except ImportError:
            pass
    if wipe is None:
        pytest.skip("_secure_wipe_bytes not found")
    immutable = b"secret"
    try:
        wipe(immutable)
    except Exception as e:
        pytest.fail(f"wipe raised on immutable bytes: {e}")
    assert immutable == b"secret"
    data = bytearray(b"sensitive")
    wipe(data)
    assert isinstance(data, bytearray)


def test_responder_initiator_flag_correct():
    """Initiator/responder round-trip using correctly split chain keys."""
    root = secrets.token_bytes(32)
    cka  = secrets.token_bytes(32)
    ckb  = secrets.token_bytes(32)
    bk   = secrets.token_bytes(32)
    ad   = b"test-ad"
    R    = _otr.RustBackedDoubleRatchet
    sm_a = _otr.SecureMemory(32); sm_a.write(root)
    sm_b = _otr.SecureMemory(32); sm_b.write(root)
    alice = R(root_key=sm_a, is_initiator=True,
              chain_key_send=cka, chain_key_recv=ckb, ad=ad, brace_key=bk)
    bob   = R(root_key=sm_b, is_initiator=False,
              chain_key_send=ckb, chain_key_recv=cka, ad=ad, brace_key=bk)
    ct, rh, nonce, tag, _, _ = alice.encrypt_message(b"Hello")
    assert bob.decrypt_message(rh, ct, nonce, tag) == b"Hello"
    ct2, rh2, nonce2, tag2, _, _ = bob.encrypt_message(b"Hi")
    assert alice.decrypt_message(rh2, ct2, nonce2, tag2) == b"Hi"


def test_smp_session_binding_prevents_cross_session():
    """Same passphrase + different session IDs produce different bound secrets."""
    fp = bytes(64)
    shared = "correct-horse"
    e_a = _otr.SMPEngine(is_initiator=True)
    e_b = _otr.SMPEngine(is_initiator=True)
    e_a.set_secret(shared, session_id=b"SESSION_A_12345_",
                   local_fingerprint=fp, remote_fingerprint=fp)
    e_b.set_secret(shared, session_id=b"SESSION_B_67890_",
                   local_fingerprint=fp, remote_fingerprint=fp)
    assert e_a.secret != e_b.secret, "Different session IDs must give different secrets"


def test_smp_minimum_length_enforced():
    """SMPEngine.set_secret rejects passphrases shorter than 8 chars."""
    for short in ["1234567", "abc", "x"]:
        e = _otr.SMPEngine(is_initiator=True)
        with pytest.raises(ValueError) as exc:
            e.set_secret(short)
        msg = str(exc.value).lower()
        assert any(kw in msg for kw in ["8", "minimum", "length", "short"]), exc.value
    e = _otr.SMPEngine(is_initiator=True)
    e.set_secret("12345678")
    assert e.state_machine.secret_set


def test_session_expiry_enforced_on_encrypt():
    """Session expiry guard raises StateMachineError before any crypto."""
    Session = otrv4plus.EnhancedOTRSession
    from otrv4plus import SessionState, StateMachineError
    session = Session(peer="test", is_initiator=True, tracer=MagicMock())
    session.session_state = SessionState.ENCRYPTED
    session.session_id = bytes(32)
    valid_rh = bytes(56) + struct.pack("!II", 0, 0)
    mock_ratchet = MagicMock()
    mock_ratchet.encrypt_message.return_value = (
        bytes(32), valid_rh, bytes(12), bytes(16), 0, [])
    mock_ratchet.consume_outgoing_kem_ct.return_value = None
    mock_ratchet.consume_outgoing_kem_ek.return_value = None
    session.ratchet = mock_ratchet
    mock_engine = MagicMock()
    session.dake_engine = mock_engine

    # Expired path: must raise StateMachineError
    mock_engine.is_session_expired.return_value = True
    with pytest.raises(StateMachineError) as exc:
        session.encrypt_with_tlvs("test", tlvs=[])
    msg = str(exc.value).lower()
    assert any(kw in msg for kw in ["exceeded", "maximum", "24", "re-establish", "dake"]),         f"Unexpected message: {exc.value}"

    # Non-expired path: expiry guard must NOT fire
    mock_engine.is_session_expired.return_value = False
    try:
        session.encrypt_with_tlvs("test", tlvs=[])
    except StateMachineError as e:
        if any(kw in str(e).lower() for kw in ["exceeded", "maximum", "24"]):
            pytest.fail(f"Expiry guard fired despite is_session_expired()=False: {e}")
    except Exception:
        pass


def test_ml_dsa_87_length_guards():
    """MLDSA87Auth has correct NIST sizes and returns False for wrong lengths."""
    MLDSA87Auth = getattr(_otr, "MLDSA87Auth", None)
    if MLDSA87Auth is None:
        pytest.skip("MLDSA87Auth not in otrv4_")
    assert MLDSA87Auth.PUB_BYTES == 2592, f"PUB_BYTES={MLDSA87Auth.PUB_BYTES}"
    assert MLDSA87Auth.SIG_BYTES == 4627, f"SIG_BYTES={MLDSA87Auth.SIG_BYTES}"
    # Wrong lengths → returns False (not raises)
    assert MLDSA87Auth.verify(bytes(MLDSA87Auth.PUB_BYTES - 1), b"m", bytes(MLDSA87Auth.SIG_BYTES)) is False
    assert MLDSA87Auth.verify(bytes(MLDSA87Auth.PUB_BYTES), b"m", bytes(MLDSA87Auth.SIG_BYTES - 1)) is False
    # Correct sizes → returns bool (may be False due to invalid crypto values)
    result = MLDSA87Auth.verify(bytes(MLDSA87Auth.PUB_BYTES), b"m", bytes(MLDSA87Auth.SIG_BYTES))
    assert isinstance(result, bool)


def test_fragment_buffer_absolute_ceiling():
    """Fragment flood guard triggers when parts dict reaches the limit."""
    import time as _time
    Buffer = otrv4plus.OTRFragmentBuffer
    buf    = Buffer()
    sender = "flood_attacker"
    MAX    = buf.max_fragments_per_sender
    assert isinstance(MAX, int) and MAX > 0

    # Pre-fill with current timestamps so _expire() doesn't evict our state
    now_ts = _time.monotonic()
    buf._buffers[sender] = {
        "total":    MAX + 1,
        "parts":    {i: f"c{i}" for i in range(MAX)},
        "first_ts": now_ts,
        "last_ts":  now_ts,
    }

    # One more fragment via spec pipe format → reaches the flood guard
    probe = f"?OTRv4|AABBCCDD|11223344|00001|{MAX + 1:05d}|data."
    with pytest.raises((ValueError, Exception)) as exc:
        buf.add_fragment(sender, probe)
    msg = str(exc.value).lower()
    assert any(kw in msg for kw in ["flood", "exceeded", "fragment", "limit", "evict"]),         f"Unexpected: {exc.value}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
