# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""F3 -- the same account on the same install keeps its identity.

Owner, after testing F2 on a handset: every sign-in gave a new fingerprint;
it should be the same for the same username on the same device. Not derived
from the username and a device value: anything that recomputes a private key
from non-secret inputs gives the key to whoever learns them. Instead each
account's identity is random, made by Rust on its first sign-in here, sealed
inside Rust under this install's key file, and kept -- on Android in the
Keystore vault (sealed a second time), on the desktop as 0600 files. Accounts
stay unlinkable (F2): independent random keys.
"""
import os
import re
import tempfile

import pytest

import test_smp_end_to_end as E

otr = E.otr
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PEER = "peer@example.test"


@pytest.fixture(autouse=True)
def _own_rate_limiter(monkeypatch):
    monkeypatch.setattr(otr, "_dake1_rate_limiter", otr.DAKE1RateLimiter())


@pytest.fixture
def home(monkeypatch):
    """A fresh HOME: one 'install'."""
    d = tempfile.mkdtemp()
    monkeypatch.setenv("HOME", d)
    return d


class DictVault:
    """The Kotlin `Vault` contract (Vault.kt): put replaces, get answers None
    for absent, remove is idempotent. Stands in for KeystoreVault, which only
    runs on a device."""

    def __init__(self):
        self.entries = {}

    def put(self, name, data):
        self.entries[name] = bytes(data)

    def get(self, name):
        return self.entries.get(name)

    def remove(self, name):
        self.entries.pop(name, None)


def _app(store):
    """A new app process using [store]: a fresh engine, as at start-up."""
    from android_bridge.app import OtrApp
    a = OtrApp.__new__(OtrApp)
    a._engine = E._manager()
    a._signed_in = False
    a._wiped = False
    a.use_identity_store(store)
    return a


def _android(vault):
    from android_bridge.account_identity import for_android
    return for_android(vault)


def _desktop():
    from android_bridge.account_identity import for_desktop
    return for_desktop()


def _signed_in_fingerprint(app, account):
    app.bind_identity_account(account)
    app.note_signed_in(account)
    return app.local_fingerprint()


def _seen_by_peer(app, account):
    peer = E._manager()
    first, _ = app._engine.handle_outgoing_message(PEER, "")
    E._relay(first, app._engine, peer, account, PEER)
    assert peer.has_encrypted_session(account)
    return peer.get_session(account).get_fingerprint()


# ── the owner's requirement ─────────────────────────────────────────────────

class TestSameAccountSameInstall:
    @pytest.mark.parametrize("kind", ["android", "desktop"])
    def test_every_sign_in_shows_the_same_fingerprint(self, home, kind):
        vault = DictVault()
        store = (lambda: _android(vault)) if kind == "android" else _desktop
        first = _signed_in_fingerprint(_app(store()), "alice@one.test")
        again = _signed_in_fingerprint(_app(store()), "alice@one.test")    # app restarted
        assert first and first == again

    def test_the_peer_sees_the_same_key_after_a_restart(self, home):
        vault = DictVault()
        a1 = _app(_android(vault))
        a1.bind_identity_account("alice@one.test")
        before = _seen_by_peer(a1, "alice@one.test")
        a2 = _app(_android(vault))
        a2.bind_identity_account("alice@one.test")
        assert _seen_by_peer(a2, "alice@one.test") == before

    def test_switching_back_to_an_account_brings_its_identity_back(self, home):
        app = _app(_android(DictVault()))
        alice = _signed_in_fingerprint(app, "alice@one.test")
        bob = _signed_in_fingerprint(app, "bob@two.test")
        assert _signed_in_fingerprint(app, "Alice@One.test/phone") == alice
        assert bob != alice

    def test_case_and_resource_do_not_make_another_identity(self, home):
        vault = DictVault()
        one = _signed_in_fingerprint(_app(_android(vault)), "alice@one.test")
        two = _signed_in_fingerprint(_app(_android(vault)), "ALICE@one.TEST/laptop")
        assert one == two


class TestStillUnlinkable:
    def test_two_accounts_on_one_install_present_different_keys(self, home):
        vault = DictVault()
        app = _app(_android(vault))
        app.bind_identity_account("alice@one.test")
        alice = _seen_by_peer(app, "alice@one.test")
        app._engine.clear_all_sessions("sign out")
        app.bind_identity_account("bob@two.test")
        assert _seen_by_peer(app, "bob@two.test") != alice

    def test_the_same_account_on_another_install_has_another_key(self, monkeypatch):
        fps = []
        for _ in range(2):
            monkeypatch.setenv("HOME", tempfile.mkdtemp())
            fps.append(_signed_in_fingerprint(_app(_android(DictVault())), "alice@one.test"))
        assert fps[0] != fps[1], "not derived from the username"

    def test_a_reinstall_or_wipe_gives_a_new_identity(self, monkeypatch):
        monkeypatch.setenv("HOME", tempfile.mkdtemp())
        before = _signed_in_fingerprint(_app(_android(DictVault())), "alice@one.test")
        # Wipe & Exit: the Keystore key goes (every vault record unopenable,
        # so the vault answers None) and ~/.otrv4plus is destroyed.
        monkeypatch.setenv("HOME", tempfile.mkdtemp())
        after = _signed_in_fingerprint(_app(_android(DictVault())), "alice@one.test")
        assert after != before


# ── what is kept, and where ─────────────────────────────────────────────────

class TestWhatIsKept:
    def test_the_vault_holds_two_records_per_account_named_by_hash(self, home):
        vault = DictVault()
        _app(_android(vault)).bind_identity_account("alice@one.test")
        names = sorted(vault.entries)
        assert len(names) == 2
        assert all(n.startswith("otrv4plus.identity.identity.") for n in names)
        assert names[1].endswith(".mldsa")
        assert not any("alice" in n or "one.test" in n for n in names), "no JID in a name"

    def test_the_records_are_sealed_inside_rust(self, home):
        """What reaches the vault is ciphertext: it opens only with this
        install's key file, which never leaves Rust."""
        vault = DictVault()
        app = _app(_android(vault))
        app.bind_identity_account("alice@one.test")
        pub = bytes(app._engine.client_profile.identity_key.public_bytes())
        for blob in vault.entries.values():
            assert pub not in blob
        from android_bridge.account_identity import identity_dir
        os.remove(os.path.join(identity_dir(), "identity.dek"))
        with pytest.raises(Exception):
            _android(vault).load("alice@one.test")

    def test_desktop_records_are_0600_files_under_the_wiped_root(self, home):
        _app(_desktop()).bind_identity_account("alice@one.test")
        from android_bridge.account_identity import identity_dir
        from android_bridge import wipe
        d = identity_dir()
        files = sorted(os.listdir(d))
        assert "identity.dek" in files and len(files) == 3
        for f in files:
            assert os.stat(os.path.join(d, f)).st_mode & 0o077 == 0
        roots = [os.path.realpath(r) for r in wipe.python_state_roots()]
        assert any(os.path.realpath(d).startswith(r + os.sep) for r in roots), \
            "Wipe & Exit destroys the key file and the desktop records"

    def test_an_unopenable_record_is_refused_never_replaced(self, home):
        from android_bridge.app_base import BridgeError
        vault = DictVault()
        _app(_android(vault)).bind_identity_account("alice@one.test")
        name = next(n for n in vault.entries if not n.endswith(".mldsa"))
        vault.entries[name] = b"\x01" + b"\x00" * 120          # tampered
        kept = dict(vault.entries)
        app = _app(_android(vault))
        before = app._engine.get_fingerprint()
        with pytest.raises(BridgeError) as err:
            app.bind_identity_account("alice@one.test")
        assert err.value.code == "identity_unavailable"
        assert vault.entries == kept, "nothing replaced"
        assert app._engine.get_fingerprint() == before
        assert getattr(app, "_identity_account", None) is None

    def test_the_identity_presented_before_is_zeroized(self, home):
        app = _app(_android(DictVault()))
        old = app._engine.client_profile
        app.bind_identity_account("alice@one.test")
        assert old.identity_key.destroyed and old.prekey.destroyed
        assert app._engine.identity_is_persistent


# ── the apps use it ─────────────────────────────────────────────────────────

class TestWiring:
    def test_the_desktop_host_keeps_identities(self, home, monkeypatch):
        from android_bridge import bootstrap
        from desktop_bridge import host
        # The runtime probe looks for PySocks by spec, which conftest stubs;
        # the engine module is the real one either way.
        monkeypatch.setattr(bootstrap, "ensure_runtime", lambda: None)
        monkeypatch.setattr(bootstrap, "load_orchestration", lambda: otr)
        app = host._real_app()
        assert getattr(app, "_identity_store", None) is not None
        first = _signed_in_fingerprint(app, "alice@one.test")
        assert _signed_in_fingerprint(host._real_app(), "alice@one.test") == first

    def test_android_passes_its_own_identity_vault(self):
        src = open(os.path.join(ROOT, "android/app/src/main/java/org/otrv4plus/android/"
                                "bridge/ChaquopyOtrCore.kt"), encoding="utf-8").read()
        call = src[src.index('"use_identity_store"'):]
        call = call[:call.index("\n            }")]
        assert '"for_android"' in call
        assert "KeystoreVault.open(appContext, KeystoreVault.IDENTITY)" in call

    def test_the_identity_vault_is_apart_from_chat_history_and_wiped(self):
        src = open(os.path.join(ROOT, "android/app/src/main/java/org/otrv4plus/android/"
                                "security/KeystoreVault.kt"), encoding="utf-8").read()
        assert re.search(r'const val IDENTITY = "identity-vault"', src)
        assert re.search(r'const val DEFAULT = "vault"', src)
        destroy = src[src.index("fun destroy(context: Context)"):]
        destroy = destroy[:destroy.index("return keyGone")]
        assert destroy.index("deleteEntry(ALIAS)") < destroy.index("for (section in SECTIONS)")

    def test_without_a_store_each_process_is_new_as_before(self):
        """F2 behaviour is what remains when no store can be had (the
        Keystore unavailable): still one identity per account."""
        from android_bridge.app import OtrApp
        a = OtrApp.__new__(OtrApp)
        a._engine = E._manager()
        a._signed_in = False
        a._wiped = False
        a.bind_identity_account("alice@one.test")
        assert not a._engine.identity_is_persistent
        assert a.bind_identity_account("bob@two.test") is True

    def test_the_terminal_record_names_are_unchanged(self):
        """Its existing per-account records (F2) keep opening."""
        import hashlib
        from otrv4plus_identity import account_tag
        old = hashlib.sha3_256(b"OTRv4+ identity record v1\x00alice@one.test").hexdigest()[:32]
        assert account_tag("Alice@One.test/x") == old
