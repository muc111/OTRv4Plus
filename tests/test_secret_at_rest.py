#!/usr/bin/env python3
"""INV-01, INV-02: what reaches disk, and in what form.

Written against the real storage classes with a real temporary directory, so
these check the bytes that land in the file rather than the intent of the
code that wrote them.
"""

import json
import os
import sys
import tempfile

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

otr = pytest.importorskip("otrv4_")

SECRET = "correct-horse-battery-staple-9911"


@pytest.fixture
def statedir():
    # tmp_path is unusable here: conftest stubs `pwd`, and pytest's tmp_path
    # factory calls getuser().
    with tempfile.TemporaryDirectory() as d:
        yield d


class TestSmpSecretsAtRest:

    def _store(self, statedir):
        return otr.SMPAutoRespondStorage(os.path.join(statedir,
                                                      "smp_secrets.json"))

    def test_the_secret_is_not_in_the_file(self, statedir):
        store = self._store(statedir)
        store.set_secret("alice@example.i2p", SECRET)
        path = os.path.join(statedir, "smp_secrets.json")
        assert os.path.exists(path), "nothing was written at all"
        raw = open(path, "rb").read()
        assert SECRET.encode() not in raw
        assert SECRET.encode("utf-16-le") not in raw

    def test_the_file_is_not_readable_json(self, statedir):
        """Named .json for history; it is a sealed blob."""
        store = self._store(statedir)
        store.set_secret("alice@example.i2p", SECRET)
        raw = open(os.path.join(statedir, "smp_secrets.json"), "rb").read()
        with pytest.raises(Exception):
            json.loads(raw.decode("utf-8"))

    def test_the_peer_name_is_not_in_the_file_either(self, statedir):
        store = self._store(statedir)
        store.set_secret("alice@example.i2p", SECRET)
        raw = open(os.path.join(statedir, "smp_secrets.json"), "rb").read()
        assert b"alice@example.i2p" not in raw, (
            "the sealed blob leaks who you have SMP secrets with")

    def test_it_round_trips(self, statedir):
        """Sealing is only useful if it opens again."""
        self._store(statedir).set_secret("alice@example.i2p", SECRET)
        assert self._store(statedir).get_secret("alice@example.i2p") == SECRET

    def test_the_file_is_owner_only(self, statedir):
        store = self._store(statedir)
        store.set_secret("alice@example.i2p", SECRET)
        mode = os.stat(os.path.join(statedir, "smp_secrets.json")).st_mode
        assert mode & 0o077 == 0, "group or other can read the sealed secrets"

    def test_two_seals_of_the_same_secret_differ(self, statedir):
        """A fresh salt and nonce per write, so the file does not reveal that
        the secret is unchanged."""
        path = os.path.join(statedir, "smp_secrets.json")
        store = self._store(statedir)
        store.set_secret("alice@example.i2p", SECRET)
        first = open(path, "rb").read()
        store.set_secret("bob@example.i2p", SECRET)
        assert open(path, "rb").read() != first


class TestTheKdfIsMemoryHard:

    def test_derive_key_uses_argon2_here(self):
        assert otr.ARGON2_AVAILABLE, (
            "argon2-cffi is not installed in this environment, so this run "
            "cannot verify the primary at-rest KDF")
        otr._derive_key(b"pw", b"0" * 16, 32)
        assert otr.kdf_backend() == "argon2id"

    def test_the_derived_key_depends_on_the_salt(self):
        a = otr._derive_key(b"pw", b"0" * 16, 32)
        b = otr._derive_key(b"pw", b"1" * 16, 32)
        assert a != b

    def test_the_derived_key_depends_on_the_password(self):
        a = otr._derive_key(b"pw-one", b"0" * 16, 32)
        b = otr._derive_key(b"pw-two", b"0" * 16, 32)
        assert a != b


class TestPasswordsNeverReachDisk:

    def test_credentials_are_not_in_the_config_repr(self):
        """Found by this test failing, and worth keeping for that.

        OTRConfig is a dataclass, so its generated __repr__ printed every
        field -- including both passwords.  The config is passed around,
        appears in debug output and lands in exception text, so `repr(cfg)`
        was on its own enough to put the account password on screen.  The
        fields are now declared repr=False.
        """
        cfg = otr.OTRConfig(sasl_pass="hunter2-secret",
                            nickserv_pass="hunter3-secret")
        rendered = repr(cfg)
        assert "hunter2-secret" not in rendered
        assert "hunter3-secret" not in rendered
        # and the values are still usable
        assert cfg.sasl_pass == "hunter2-secret"
        assert cfg.nickserv_pass == "hunter3-secret"

    def test_credentials_are_not_in_the_config_str(self):
        cfg = otr.OTRConfig(sasl_pass="hunter2-secret")
        assert "hunter2-secret" not in str(cfg)

    def test_the_config_has_no_serialisation_hook(self):
        cfg = otr.OTRConfig(sasl_pass="hunter2")
        for hook in ("to_json", "save", "serialize", "asdict"):
            assert not hasattr(cfg, hook), (
                "OTRConfig grew a %s hook, which is one call away from "
                "writing credentials somewhere" % hook)

    def test_credentials_are_cleared_after_use(self):
        """Setting to None drops the reference.  It cannot overwrite the
        buffer -- Python strings are immutable -- which is why INV-02 records
        that limit rather than claiming zeroization."""
        import inspect
        src = inspect.getsource(otr)
        assert "self.config.sasl_pass = None" in src
        assert "self.config.nickserv_pass = None" in src

    def test_the_password_prompts_use_getpass(self):
        import inspect
        src = inspect.getsource(otr)
        assert 'getpass.getpass("SASL password: ")' in src
        assert 'getpass.getpass("NickServ password: ")' in src

    def test_no_credential_reaches_a_write_call(self):
        """Every write/dump call in the engine, checked for credential names."""
        import ast
        import inspect
        tree = ast.parse(inspect.getsource(otr))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            f = node.func
            name = getattr(f, "attr", getattr(f, "id", ""))
            if name not in ("write", "dump", "dumps"):
                continue
            text = ast.dump(node)
            for cred in ("sasl_pass", "nickserv_pass", "_master_passphrase"):
                assert cred not in text, (
                    "%s appears in a %s() call at line %d"
                    % (cred, name, node.lineno))
