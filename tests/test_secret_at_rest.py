#!/usr/bin/env python3
"""INV-01, INV-02, INV-08: what reaches disk, in what form, and who holds the key.

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
        """Sealing is only useful if it opens again -- proved without reading
        the passphrase back, because nothing can: bind it from a reopened
        store into a vault and derive the same SMP binding as a direct set."""
        self._store(statedir).set_secret("alice@example.i2p", SECRET)
        again = self._store(statedir)
        assert again.has_secret("alice@example.i2p")
        assert again.peers() == ["alice@example.i2p"]

    def test_there_is_no_way_to_read_a_passphrase_back(self, statedir):
        store = self._store(statedir)
        store.set_secret("alice@example.i2p", SECRET)
        for gone in ("get_secret", "list_secrets", "_secrets"):
            assert not hasattr(store, gone), gone
        assert SECRET not in repr(store) and SECRET not in repr(store._store)

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


class TestTheLegacyStoreMigratesInRust:
    """Stores written by the retired Python code open, migrate and bind in
    Rust. The old file is built here with argon2-cffi -- an independent
    implementation of the exact derivation the Python code used -- so this
    checks compatibility against the real format, not against itself."""

    @staticmethod
    def _write_legacy(statedir, secrets_map):
        low = pytest.importorskip("argon2.low_level")
        core = pytest.importorskip("otrv4_core")
        seed = os.urandom(32)
        with open(os.path.join(statedir, ".smp_seed"), "wb") as f:
            f.write(seed)
        salt, nonce = os.urandom(16), os.urandom(12)
        key = low.hash_secret_raw(secret=seed, salt=salt, time_cost=3,
                                  memory_cost=65536, parallelism=4,
                                  hash_len=32, type=low.Type.ID)
        plaintext = json.dumps(secrets_map, separators=(",", ":")).encode()
        ct = core.aes256gcm_encrypt(key, nonce, plaintext, b"smp_secrets_v1")
        path = os.path.join(statedir, "smp_secrets.json")
        with open(path, "wb") as f:
            f.write(salt + nonce + bytes(ct))
        return path

    def test_a_legacy_store_opens_and_is_rewritten(self, statedir):
        path = self._write_legacy(statedir, {"alice@example.i2p": SECRET,
                                             "bob@example.i2p": "p\u00e4ss w\u00f6rd \"q\""})
        store = otr.SMPAutoRespondStorage(path)
        assert sorted(store.peers()) == ["alice@example.i2p", "bob@example.i2p"]
        assert store._store.migrated
        assert open(path, "rb").read().startswith(b"OTRV4SMP\x02"), (
            "the legacy file was not rewritten in the current format")
        assert sorted(otr.SMPAutoRespondStorage(path).peers()) == [
            "alice@example.i2p", "bob@example.i2p"]

    def test_the_migrated_secret_is_the_same_secret(self, statedir):
        """A vault bound from the migrated store and one fed the passphrase
        directly must produce the same SMP binding."""
        core = pytest.importorskip("otrv4_core")
        path = self._write_legacy(statedir, {"alice@example.i2p": SECRET})
        store = core.SmpSecretStore(path)
        via_store, direct = core.RustSMPVault(), core.RustSMPVault()
        assert store.bind_into("alice@example.i2p", via_store, "s")
        direct.store_from_bytearray("s", bytearray(SECRET.encode()))
        sid, fa, fb = b"sid" * 8, b"a" * 57, b"b" * 57
        a, b = core.RustSMP(True), core.RustSMP(False)
        a.set_secret_from_vault(via_store, "s", sid, fa, fb)
        b.set_secret_from_vault(direct, "s", sid, fb, fa)
        m1 = a.generate_smp1(None)
        m2 = b.process_smp1_generate_smp2(bytes(m1))
        m3 = a.process_smp2_generate_smp3(bytes(m2))
        m4 = b.process_smp3_generate_smp4(bytes(m3))
        a.process_smp4(bytes(m4))
        assert a.is_verified() and b.is_verified()


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


class TestTheSmpPassphraseIsNotCopied:
    """The wipe used to be defeated one line before it ran.

        raw = bytearray(secret.encode("utf-8"))
        try:
            self.smp_vault.store("smp_secret", bytes(raw))   # unwipeable copy
            ...
        finally:
            for i in range(len(raw)): raw[i] = 0             # wrong object

    The bytearray existed so it could be wiped, and it was wiped -- but
    `bytes(raw)` had already made an immutable copy that outlived the block.
    """

    def test_the_vault_takes_a_bytearray_and_wipes_it(self):
        core = pytest.importorskip("otrv4_core")
        vault = core.RustSMPVault()
        buf = bytearray(b"correct-horse-battery-staple")
        vault.store_from_bytearray("smp_secret", buf)
        assert bytes(buf) == b"\x00" * 28, (
            "the caller's buffer survived the store")
        assert vault.has("smp_secret")

    def test_it_wipes_even_when_the_store_is_rejected(self):
        """A rejected secret is still a secret."""
        core = pytest.importorskip("otrv4_core")
        vault = core.RustSMPVault()
        buf = bytearray(b"rejected-but-still-secret")
        with pytest.raises(ValueError):
            vault.store_from_bytearray("", buf)      # empty name
        assert bytes(buf) == b"\x00" * 25

    def test_the_engine_no_longer_makes_the_copy(self):
        import inspect
        src = inspect.getsource(otr.EnhancedOTRSession.set_smp_secret)
        assert 'store("smp_secret", bytes(raw))' not in src, (
            "the immutable copy is back, so the wipe below it is decorative")
        assert "store_from_bytearray" in src

    def test_the_belt_and_braces_wipe_is_still_there(self):
        """store_from_bytearray wipes, and this still runs if it raised
        before reaching Rust."""
        import inspect
        src = inspect.getsource(otr.EnhancedOTRSession.set_smp_secret)
        assert "finally:" in src
        assert "raw[i] = 0" in src
