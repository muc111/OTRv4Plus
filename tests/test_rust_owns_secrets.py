#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Enforces INV-08: Python orchestrates, Rust owns the secrets.

WHAT WAS STILL CROSSING
=======================
INV-08 said ratchet keys never cross the PyO3 boundary. The root and chain
keys did not -- but four other session secrets did, on every session:

  * `X448KeyHandle.dh(peer)` returned the X448 shared secret as Python
    `bytes`, and the double ratchet called it on EVERY DH ratchet step
    (twice on the receive side) before handing the secret straight back to
    `RustDoubleRatchet.send_ratchet` / `decrypt_new_dh`.
  * The brace rotation kept its ML-KEM decapsulation key in a Python
    `bytearray` (`MLKEM1024BraceKEM`), and the ML-KEM shared secret came
    back as `bytes` to be passed to `rotate_brace_key`.
  * The voice exchange returned both the X448 and the ML-KEM shared secret
    to Python (`RustVoiceKex.agree`, `_RustKem.decaps`), and kept the
    decapsulation key in a `bytearray`.
  * `MLDSA87Auth` held the 4896-byte ML-DSA-87 signing key in a `bytearray`
    for the life of every DAKE, and `bytes(priv)` made a fresh unwipeable
    copy on every signature.

Each is now an operation inside Rust on an opaque handle. Python receives
public values -- public keys, ciphertexts, signatures -- and one-way tags.

This module checks the surface (the leaking methods are gone), the
production source (nothing reintroduces the raw-secret primitives), and the
behaviour (a real exchange with DH steps and brace rotations works through
the handles alone).
"""

import ast
import os
import secrets
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

core = pytest.importorskip("otrv4_core")


def _public(obj):
    return {n for n in dir(obj) if not n.startswith("_")}


# ---------------------------------------------------------------------------
# 1. The surface: the methods that handed secrets over do not exist
# ---------------------------------------------------------------------------

class TestTheLeakingMethodsAreGone:

    def test_an_x448_handle_cannot_agree_in_python(self):
        handle = core.generate_x448_keypair()
        assert not hasattr(handle, "dh"), (
            "X448KeyHandle.dh returns the shared secret to Python")
        assert _public(handle) == {"public_bytes", "zeroize", "destroyed"}

    def test_the_ratchet_takes_no_shared_secret_from_python(self):
        assert not hasattr(core.RustDoubleRatchet, "rotate_brace_key")
        r = core.RustDoubleRatchet(b"\x01" * 32, b"\x02" * 32, b"\x03" * 32,
                                   b"\x04" * 32, b"\x05" * 56, True)
        with pytest.raises(TypeError):
            r.send_ratchet(secrets.token_bytes(56), secrets.token_bytes(56))
        with pytest.raises(TypeError):
            r.decrypt_new_dh(b"h", b"c", b"\x00" * 12, b"\x00" * 16,
                             secrets.token_bytes(56), secrets.token_bytes(56))

    def test_the_voice_exchange_returns_no_secret(self):
        kex = core.RustVoiceKex(True)
        assert not hasattr(kex, "agree")
        assert not hasattr(kex, "agree_into_root")

    def test_an_mlkem_keypair_exposes_only_its_public_half(self):
        kp = core.MlKem1024Keypair()
        assert _public(kp) == {"encap_key", "spent", "zeroize"}
        assert len(bytes(kp.encap_key)) == 1568

    def test_an_mldsa_handle_exposes_only_its_public_half(self):
        h = core.MlDsa87KeyHandle()
        assert _public(h) == {"public_bytes", "sign", "zeroize", "destroyed"}
        sig = bytes(h.sign(b"m"))
        assert core.mldsa87_verify(bytes(h.public_bytes), b"m", sig)
        h.zeroize()
        with pytest.raises(RuntimeError):
            h.sign(b"m")


# ---------------------------------------------------------------------------
# 2. The production source does not reach for the raw-secret primitives
# ---------------------------------------------------------------------------

#: Calls that put a secret into a Python object. They remain in the module
#: for known-answer and cross-implementation tests, which need raw values.
RAW_SECRET_PRIMITIVES = {"mlkem1024_keygen", "mlkem1024_encaps",
                         "mlkem1024_decaps", "mldsa87_keygen", "mldsa87_sign"}

#: Where they may still appear in shipped code, and why.
ALLOWED = {
    # Startup self-test on throwaway keys: no session secret involved.
    ("android_bridge/diagnostics.py", "*"),
}

PRODUCTION = ["otrv4+.py", "otrv4plus_voice.py", "otrv4plus_xmpp.py",
              "otrv4plus_filetransfer.py", "otrv4plus_identity.py"] + [
    "android_bridge/" + f for f in sorted(os.listdir(os.path.join(ROOT, "android_bridge")))
    if f.endswith(".py")]


def _raw_calls(relpath):
    src = open(os.path.join(ROOT, relpath), encoding="utf-8").read()
    tree = ast.parse(src)
    found = []

    def walk(node, owner):
        for child in ast.iter_child_nodes(node):
            here = owner
            if isinstance(child, ast.ClassDef):
                here = child.name
            if isinstance(child, ast.Call):
                f = child.func
                name = f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", "")
                if name in RAW_SECRET_PRIMITIVES:
                    found.append((owner, name, child.lineno))
            walk(child, here)

    walk(tree, "<module>")
    return found


class TestProductionDoesNotHoldRawSecrets:

    @pytest.mark.parametrize("relpath", PRODUCTION)
    def test_no_raw_secret_primitive_outside_the_allowlist(self, relpath):
        if not os.path.exists(os.path.join(ROOT, relpath)):
            pytest.skip("%s not in this checkout" % relpath)
        bad = [(o, n, ln) for (o, n, ln) in _raw_calls(relpath)
               if (relpath, o) not in ALLOWED and (relpath, "*") not in ALLOWED]
        assert not bad, "%s calls a raw-secret primitive: %r" % (relpath, bad)

    def test_the_ratchet_never_builds_a_python_held_kem_key(self):
        src = open(os.path.join(ROOT, "otrv4+.py"), encoding="utf-8").read()
        tree = ast.parse(src)
        made = [n.lineno for n in ast.walk(tree)
                if isinstance(n, ast.Call)
                and getattr(n.func, "id", "") == "MLKEM1024BraceKEM"]
        assert not made, "MLKEM1024BraceKEM() instantiated at %r" % made

    def test_the_brace_kem_class_is_sizes_only(self):
        # It wrapped keygen/encaps/decaps and returned the shared secret as
        # Python bytes. Nothing used it; it is now three integers.
        cls = _engine().MLKEM1024BraceKEM
        for name in ("__init__", "encapsulate", "decapsulate", "zeroize"):
            assert name not in vars(cls), "MLKEM1024BraceKEM.%s is back" % name
        assert (cls.EK_BYTES, cls.CT_BYTES, cls.SS_BYTES) == (1568, 1568, 32)

    def test_the_voice_exchange_does_not_use_the_python_kem(self):
        import otrv4plus_voice as V
        src = open(os.path.join(ROOT, "otrv4plus_voice.py"), encoding="utf-8").read()
        body = src[src.index("class VoiceKeyExchange"):src.index("class ReplayWindow")]
        assert "self._kem." not in body
        assert "_mlkem_dk" not in body
        kex = V.VoiceKeyExchange(True)
        assert isinstance(kex._kex, core.RustVoiceKex)

    def test_the_pseudo_extra_symmetric_key_is_gone(self):
        # It was SHA3 over the SSID and the peer's TLV value -- public inputs
        # -- kept on the session and read by nothing.
        src = open(os.path.join(ROOT, "otrv4+.py"), encoding="utf-8").read()
        assert "_last_extra_sym_key" not in src
        assert "OTRv4-EXTRA-SYM" not in src


# ---------------------------------------------------------------------------
# 3. Behaviour: a real exchange runs through handles alone
# ---------------------------------------------------------------------------

def _engine():
    return sys.modules.get("otrv4_") or pytest.importorskip("otrv4_")


def _pair(rekey_interval=2):
    otr = _engine()
    rk, cka, ckb, bk = (secrets.token_bytes(32) for _ in range(4))
    common = dict(root_key=rk, brace_key=bk, rekey_interval=rekey_interval)
    a = otr.DoubleRatchet(is_initiator=True, chain_key_send=cka,
                          chain_key_recv=ckb, **common)
    b = otr.DoubleRatchet(is_initiator=False, chain_key_send=ckb,
                          chain_key_recv=cka, **common)
    return a, b


def _until_a_brace_key_is_pending(a, b):
    """Exchange until `a` has taken a DH step and prepared a brace keypair."""
    for i in range(20):
        s, r = (a, b) if i % 2 == 0 else (b, a)
        ct, h, n, t, *_ = s.encrypt_message(b"x")
        r.decrypt_message(h, ct, n, t)
        if a._brace_kem_local is not None:
            return
    pytest.fail("the ratchet never prepared a brace rotation")


class TestTheRatchetRunsOnHandles:

    def test_dh_steps_and_brace_rotations_converge(self):
        a, b = _pair()
        rotations = 0
        for i in range(30):
            s, r = (a, b) if i % 2 == 0 else (b, a)
            ct, h, n, t, *_ = s.encrypt_message(b"m%d" % i)
            pt, _ = r.decrypt_message(h, ct, n, t)
            assert pt == b"m%d" % i
            ek = s.consume_outgoing_kem_ek()
            if ek:
                r.process_incoming_kem_ek(ek)
                s.process_incoming_kem_ct(r.consume_outgoing_kem_ct())
                rotations += 1
        assert a.ratchet_id > 5 and b.ratchet_id > 5, "no DH steps happened"
        assert rotations > 5, "no brace rotations happened"
        # Tags of equal keys are equal: both ends hold the same brace key.
        assert a._brace_key == b._brace_key

    def test_the_ratchet_keys_are_handles(self):
        a, b = _pair()
        _until_a_brace_key_is_pending(a, b)
        assert isinstance(a.dh_ratchet_local, core.X448KeyHandle)
        assert isinstance(a._brace_kem_local, core.MlKem1024Keypair)

    def test_decapsulation_spends_the_pending_keypair(self):
        a, b = _pair()
        _until_a_brace_key_is_pending(a, b)
        pending = a._brace_kem_local
        b.process_incoming_kem_ek(a.consume_outgoing_kem_ek())
        a.process_incoming_kem_ct(b.consume_outgoing_kem_ct())
        assert pending.spent
        assert a._brace_kem_local is None

    def test_the_mirrors_are_tags_not_keys(self):
        a, _ = _pair()
        tags = a._rust.state_tags()
        assert a.root_key.read() == bytes(tags["root"])
        assert a.chain_key_send.read() == bytes(tags["chain_send"])
        assert a._brace_key == bytes(tags["brace"])

    def test_the_dake_signing_key_is_a_handle(self):
        otr = _engine()
        auth = otr.MLDSA87Auth()
        assert isinstance(auth._priv, core.MlDsa87KeyHandle)
        sig = auth.sign(b"transcript")
        assert otr.MLDSA87Auth.verify(auth.pub_bytes, b"transcript", sig)
        auth.zeroize()
        assert auth._priv is None


class TestTheRatchetIsBuiltOnlyFromTheDake:
    """`RustBackedDoubleRatchet(root_key=..., chain_key_send=...)` builds a
    ratchet from keys already in Python, deriving missing chain keys with the
    Python SHAKE-256 KDF. The test suite needs that -- it is how a ratchet is
    built from known keys -- but production must only ever use
    `from_dake_output`, which moves the keys Rust-to-Rust. The legacy DAKE
    branches, `_unpack_session_keys`, the Python-key fallback in
    `_initialize_ratchet` and the uncalled `_kdf_ck` were removed; this keeps
    a direct construction from coming back."""

    @pytest.mark.parametrize("relpath", PRODUCTION)
    def test_no_production_code_constructs_a_ratchet_from_keys(self, relpath):
        if not os.path.exists(os.path.join(ROOT, relpath)):
            pytest.skip("%s not in this checkout" % relpath)
        tree = ast.parse(open(os.path.join(ROOT, relpath), encoding="utf-8").read())
        made = [n.lineno for n in ast.walk(tree)
                if isinstance(n, ast.Call)
                and (getattr(n.func, "id", "") or getattr(n.func, "attr", ""))
                in ("RustBackedDoubleRatchet", "DoubleRatchet")]
        assert not made, "%s builds a ratchet from raw keys at %r" % (relpath, made)

    def test_the_legacy_paths_are_gone(self):
        src = open(os.path.join(ROOT, "otrv4+.py"), encoding="utf-8").read()
        for gone in ("def _unpack_session_keys", "def _kdf_ck",
                     "use_output_api", "legacy v10.6.2 path"):
            assert gone not in src, gone


class TestAtRestKeysAreReadByRustOnly:
    """0.7.0: the SMP auto-respond store and the Termux identity DEK moved into
    Rust (`Rust/src/at_rest.rs`). No production Python reads a key file, and
    neither Rust object can hand a key or passphrase back."""

    KEY_FILES = (".smp_seed", ".device_seed")

    @pytest.mark.parametrize("relpath", PRODUCTION)
    def test_no_python_opens_a_key_file(self, relpath):
        if not os.path.exists(os.path.join(ROOT, relpath)):
            pytest.skip("%s not in this checkout" % relpath)
        tree = ast.parse(open(os.path.join(ROOT, relpath), encoding="utf-8").read())
        opened = []
        for n in ast.walk(tree):
            if isinstance(n, ast.Call) and getattr(n.func, "id", "") == "open":
                seg = ast.dump(n)
                if any(k in seg for k in self.KEY_FILES):
                    opened.append(n.lineno)
        assert not opened, "%s opens a key file itself at %r" % (relpath, opened)

    def test_the_rust_objects_have_no_secret_getter(self):
        store = core.SmpSecretStore(None)
        store.set("a@x", "a long passphrase")
        public = {n for n in dir(store) if not n.startswith("_")}
        assert public == {"bind_into", "clear", "clear_memory", "has",
                          "legacy_unreadable", "migrated", "peers",
                          "persistent", "remove", "set"}, public
        assert "a long passphrase" not in repr(store)
        dek_api = {n for n in dir(core.FileDek) if not n.startswith("_")}
        assert dek_api == {"destroyed", "load_or_create", "open", "seal", "zeroize"}, dek_api

    def test_the_termux_dek_handle_has_no_raw_key(self):
        import otrv4plus_identity as I
        assert not hasattr(I._FileDekHandle, "raw_key_for_rust")
        src = open(os.path.join(ROOT, "otrv4plus_identity.py"), encoding="utf-8").read()
        assert "FileDek.load_or_create" in src
        assert "token_bytes(32)" not in src, "the DEK is generated in Python again"

    def test_a_bytearray_secret_is_zeroed_by_the_store(self):
        store = core.SmpSecretStore(None)
        buf = bytearray(b"typed passphrase")
        store.set("a@x", buf)
        assert buf == bytearray(len(buf))
