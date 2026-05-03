"""
smp_engine_compat.py — SMPEngine compatibility wrapper for the test suite.

SMPEngine was removed from otrv4+.py when the Rust SMP migration completed
(v10.5.10). This module re-creates a thin Python wrapper around the Rust
RustSMP + RustSMPVault APIs so that all existing test references to:

    otr.SMPEngine(is_initiator=True)
    engine.set_secret("passphrase", session_id=..., ...)
    engine.secret              → bytes (derived secret for comparison)
    engine.state_machine       → object with .secret_set attribute
    engine._vault              → RustSMPVault
    engine._clear_math_state() → clears vault

continue to work without modification.
"""

import os
import sys
import hashlib

try:
    from otrv4_core import RustSMP, RustSMPVault
    _RUST_AVAILABLE = True
except ImportError:
    _RUST_AVAILABLE = False

# ── Minimal state machine object expected by tests ────────────────────────────

class _SMPStateMachine:
    """Lightweight state tracker that mirrors what tests check."""
    def __init__(self):
        self.secret_set = False
        self.state      = "IDLE"

    def mark_secret_set(self):
        self.secret_set = True
        self.state = "READY"

    def reset(self):
        self.secret_set = False
        self.state = "IDLE"


# ── KDF matching smp.rs set_secret exactly ───────────────────────────────────
# 50k-round SHAKE-256 chain + HMAC-SHA3-512 with canonical fingerprint ordering
# Used ONLY to expose the derived value for assertion in tests.

def _derive_smp_secret(
    passphrase:        str,
    session_id:        bytes = b'',
    local_fingerprint:  bytes = b'',
    remote_fingerprint: bytes = b'',
    is_initiator:      bool  = True,
) -> bytes:
    """
    Pure-Python re-implementation of smp.rs::SmpState::set_secret().
    Used by tests that compare e_a.secret != e_b.secret.
    """
    KDF_ROUNDS = 50_000

    # 1. SHAKE-256 chain
    import hashlib
    h = hashlib.shake_256()
    h.update(b"OTRv4+SMP-v2\x00")
    h.update(passphrase.encode('utf-8'))
    state = h.digest(64)

    for i in range(KDF_ROUNDS - 1):
        h2 = hashlib.shake_256()
        h2.update(i.to_bytes(4, 'big'))
        h2.update(state)
        state = h2.digest(64)

    # 2. HMAC-SHA3-512 session binding with canonical fingerprint ordering
    import hmac as _hmac
    hkey_h = hashlib.sha3_512(session_id).digest()

    fp_a, fp_b = (
        (local_fingerprint,  remote_fingerprint)
        if local_fingerprint <= remote_fingerprint
        else (remote_fingerprint, local_fingerprint)
    )

    mac = _hmac.new(hkey_h, digestmod=hashlib.sha3_512)
    mac.update(fp_a)
    mac.update(fp_b)
    mac.update(state)
    binding = mac.digest()

    # 3. Reduce mod order (2048-bit safe prime)
    PRIME_HEX = (
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
        "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
        "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
        "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
        "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
        "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
        "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
        "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
        "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
        "15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64"
        "ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"
        "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B"
        "F12FFA06D98A0864D87602733EC86A64521F2B18177B200C"
        "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31"
        "43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF"
    )
    prime = int(PRIME_HEX, 16)
    order = (prime - 1) >> 1
    n = int.from_bytes(binding, 'big') % order
    if n == 0:
        n = 1

    return n.to_bytes(256, 'big')


# ── SMPEngine wrapper ─────────────────────────────────────────────────────────

class SMPEngine:
    """
    Python wrapper around RustSMP + RustSMPVault.

    API contract (used by tests):
        eng = SMPEngine(is_initiator=True)
        eng.set_secret("pass", session_id=..., local_fingerprint=...,
                                              remote_fingerprint=...)
        eng.secret            → bytes (derived value, for comparison only)
        eng.state_machine.secret_set → bool
        eng._vault            → RustSMPVault instance
        eng._clear_math_state() → clears vault and resets state
        eng.generate_smp1()   → bytes
        eng.process_smp1_generate_smp2(data) → bytes
        eng.process_smp2_generate_smp3(data) → bytes
        eng.process_smp3_generate_smp4(data) → bytes
        eng.process_smp4(data) → bool
        eng.is_verified()     → bool
        eng.is_failed()       → bool
    """

    def __init__(self, is_initiator: bool = True):
        self.is_initiator  = is_initiator
        self.state_machine = _SMPStateMachine()
        self._secret_derived: bytes = b''

        if _RUST_AVAILABLE:
            self._rust_smp = RustSMP(is_initiator)
            self._vault    = RustSMPVault()
        else:
            self._rust_smp = None
            self._vault    = None

    # ── Secret binding ────────────────────────────────────────────────────────

    def set_secret(
        self,
        passphrase:         str,
        session_id:         bytes = b'',
        local_fingerprint:  bytes = b'',
        remote_fingerprint: bytes = b'',
    ):
        if len(passphrase) < 8:
            raise ValueError(
                f"SMP secret must be at least 8 characters (got {len(passphrase)})")

        # Derive comparison value in Python (matches Rust KDF exactly)
        self._secret_derived = _derive_smp_secret(
            passphrase, session_id, local_fingerprint, remote_fingerprint,
            self.is_initiator)
        self.state_machine.mark_secret_set()

        if self._rust_smp is not None and self._vault is not None:
            # Store bytes in Rust vault, wipe bytearray immediately
            raw = bytearray(passphrase.encode('utf-8'))
            try:
                self._vault.store("secret", bytes(raw))
                self._rust_smp.set_secret_from_vault(
                    self._vault, "secret",
                    session_id, local_fingerprint, remote_fingerprint)
            finally:
                for i in range(len(raw)):
                    raw[i] = 0
                del raw

    # ── Test-facing secret property ───────────────────────────────────────────

    @property
    def secret(self) -> bytes:
        """Derived secret bytes (for cross-session comparison in tests only)."""
        return self._secret_derived

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def _clear_math_state(self):
        """Zeroize vault and reset state. Mirrors EnhancedOTRSession cleanup."""
        if self._vault is not None:
            self._vault.clear()
        if self._rust_smp is not None:
            self._rust_smp.destroy()
            # Re-create for potential reuse
            try:
                self._rust_smp = RustSMP(self.is_initiator)
            except Exception:
                self._rust_smp = None
        self._secret_derived = b''
        self.state_machine.reset()

    # ── Protocol steps ────────────────────────────────────────────────────────

    def generate_smp1(self, question: str = None) -> bytes:
        if self._rust_smp is None:
            raise RuntimeError("Rust SMP not available")
        return bytes(self._rust_smp.generate_smp1(question))

    def process_smp1_generate_smp2(self, data: bytes) -> bytes:
        if self._rust_smp is None:
            raise RuntimeError("Rust SMP not available")
        return bytes(self._rust_smp.process_smp1_generate_smp2(data))

    def process_smp2_generate_smp3(self, data: bytes) -> bytes:
        if self._rust_smp is None:
            raise RuntimeError("Rust SMP not available")
        return bytes(self._rust_smp.process_smp2_generate_smp3(data))

    def process_smp3_generate_smp4(self, data: bytes) -> bytes:
        if self._rust_smp is None:
            raise RuntimeError("Rust SMP not available")
        return bytes(self._rust_smp.process_smp3_generate_smp4(data))

    def process_smp4(self, data: bytes) -> bool:
        if self._rust_smp is None:
            raise RuntimeError("Rust SMP not available")
        return bool(self._rust_smp.process_smp4(data))

    def is_verified(self) -> bool:
        if self._rust_smp is None:
            return False
        return bool(self._rust_smp.is_verified())

    def is_failed(self) -> bool:
        if self._rust_smp is None:
            return True
        return bool(self._rust_smp.is_failed())

    def get_phase(self) -> str:
        if self._rust_smp is None:
            return "UNAVAILABLE"
        return self._rust_smp.get_phase()
