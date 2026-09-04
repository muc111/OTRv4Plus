#!/usr/bin/env python3
"""INV-14: no home-grown cryptography where the Rust core supplies it.

`otrv4plus_log.py` used to carry its own AEAD -- a SHAKE-256 keystream XORed
over the plaintext with a truncated HMAC-SHA3-512 tag -- and wrote every
line anyone typed to `~/.otrv4plus/logs/channels/*.enc`.  A `persistent=True`
mode kept those files and their key across sessions.  No caller ever set it,
but the docstring said XMPP did, and one constructor argument stood between
that claim and it becoming true.

It was deleted rather than re-based onto the Rust AEAD, because the module
does not need to encrypt anything: in-memory scrollback that dies with the
process has nothing to protect at rest.

These tests fail if a cipher, a key, or a file write comes back.
"""

import ast
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

LOG_MODULE = os.path.join(ROOT, "otrv4plus_log.py")


def _src(path=LOG_MODULE):
    return open(path, encoding="utf-8").read()


def _code_only(path=LOG_MODULE):
    """Source with docstrings and comments removed.

    The module docstring describes the deleted cipher on purpose, so a raw
    substring search would match the explanation of the removal.
    """
    tree = ast.parse(_src(path))
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef,
                             ast.AsyncFunctionDef)):
            body = node.body
            if (body and isinstance(body[0], ast.Expr)
                    and isinstance(body[0].value, ast.Constant)
                    and isinstance(body[0].value.value, str)):
                body.pop(0)
    return ast.unparse(tree)


class TestTheCipherIsGone:

    @pytest.mark.parametrize("primitive", [
        "shake_256", "shake_128", "sha3_512", "hmac", "os.urandom",
        "AESGCM", "Cipher", "ChaCha20",
    ])
    def test_no_cryptographic_primitive_is_used(self, primitive):
        assert primitive not in _code_only(), (
            "%s is back in otrv4plus_log.py; if this module needs "
            "cryptography it must use the Rust core, and if it needs the "
            "Rust core it should not be storing anything" % primitive)

    def test_no_aead_functions(self):
        code = _code_only()
        for name in ("_aead_encrypt", "_aead_decrypt", "_DOM_ENC", "_DOM_MAC"):
            assert name not in code

    def test_no_key_material_at_all(self):
        code = _code_only()
        for name in ("_key", "_KEY_FILE", "channel_log.key",
                     "_load_or_create_key"):
            assert name not in code, "%s survived the deletion" % name

    def test_the_module_imports_no_crypto(self):
        tree = ast.parse(_src())
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(a.name.split(".")[0] for a in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])
        for banned in ("hashlib", "hmac", "cryptography", "otrv4_core",
                       "secrets", "struct"):
            assert banned not in imported, (
                "otrv4plus_log.py imports %s again" % banned)


class TestNothingReachesDisk:

    def test_no_file_is_opened(self):
        code = _code_only()
        for pattern in ("open(", "Path(", "mkdir", "write_bytes",
                        "read_bytes", "unlink", "chmod"):
            assert pattern not in code, (
                "%s is back: this module must not touch the filesystem"
                % pattern)

    def test_the_pathlib_import_is_gone(self):
        assert "pathlib" not in _src()

    def test_no_persistent_parameter(self):
        code = _code_only()
        assert "persistent" not in code, (
            "the persistent flag is back; it is the one argument that turned "
            "in-memory scrollback into a permanent on-disk transcript")

    def test_the_manager_takes_no_arguments(self):
        """A caller must not be able to ask for persistence at all."""
        mod = pytest.importorskip("otrv4plus_log")
        with pytest.raises(TypeError):
            mod.ChannelLogManager(persistent=True)
        mod.ChannelLogManager()          # the only valid construction


class TestCallersDoNotAskForPersistence:

    @pytest.mark.parametrize("client", ["otrv4plus_xmpp.py", "otrv4+.py"])
    def test_no_client_passes_persistent(self, client):
        src = _src(os.path.join(ROOT, client))
        assert "persistent=True" not in src
        assert "_ChannelLogManager(persistent" not in src

    @pytest.mark.parametrize("client", ["otrv4plus_xmpp.py", "otrv4+.py"])
    def test_clients_still_construct_one(self, client):
        """Deleting the persistence must not have deleted the scrollback."""
        assert "_ChannelLogManager()" in _src(os.path.join(ROOT, client))


class TestItStillWorks:

    @pytest.fixture
    def mgr(self):
        mod = pytest.importorskip("otrv4plus_log")
        return mod.ChannelLogManager()

    def test_append_and_read_back(self, mgr):
        mgr.append("alice@example.i2p", "hello")
        mgr.append("alice@example.i2p", "again")
        assert mgr.read_recent("alice@example.i2p") == ["hello", "again"]

    def test_channels_are_separate(self, mgr):
        mgr.append("a@x", "for a")
        mgr.append("b@x", "for b")
        assert mgr.read_recent("a@x") == ["for a"]
        assert mgr.read_recent("b@x") == ["for b"]

    def test_ansi_is_stripped(self, mgr):
        mgr.append("a@x", "\x1b[31mred\x1b[0m")
        assert mgr.read_recent("a@x") == ["red"]

    def test_read_recent_honours_n(self, mgr):
        for i in range(10):
            mgr.append("a@x", "line %d" % i)
        assert mgr.read_recent("a@x", n=3) == ["line 7", "line 8", "line 9"]

    def test_lines_are_bounded(self, mgr):
        mod = pytest.importorskip("otrv4plus_log")
        for i in range(mod.MAX_LINES_PER_CHANNEL + 500):
            mgr.append("a@x", "l%d" % i)
        assert len(mgr.read_recent("a@x", n=10**9)) == mod.MAX_LINES_PER_CHANNEL

    def test_channels_are_bounded(self, mgr):
        mod = pytest.importorskip("otrv4plus_log")
        for i in range(mod.MAX_CHANNELS + 20):
            mgr.append("peer%d@x" % i, "hi")
        assert len(mgr._logs) <= mod.MAX_CHANNELS
        # the earliest channels were evicted, the most recent survive
        assert mgr.read_recent("peer%d@x" % (mod.MAX_CHANNELS + 19)) == ["hi"]

    def test_close_drops_everything(self, mgr):
        mgr.append("a@x", "secret-ish content")
        mgr.close()
        assert mgr.read_recent("a@x") == []
        assert mgr._logs == {}

    def test_close_is_idempotent(self, mgr):
        mgr.close()
        mgr.close()

    def test_append_after_close_is_a_no_op(self, mgr):
        mgr.close()
        mgr.append("a@x", "should not land")
        assert mgr.read_recent("a@x") == []

    def test_wipe_is_close(self, mgr):
        mgr.append("a@x", "x")
        mgr.wipe()
        assert mgr.read_recent("a@x") == []

    def test_unknown_channel_reads_empty(self, mgr):
        assert mgr.read_recent("never@seen") == []
