# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""P1 (docs/SECURITY_ISSUES.md): contact pins are kept across restarts.

Found by the audit of 2026-10-26: the Android and desktop engines kept
`TrustDatabase` in memory, so after the app restarted a contact presenting
another key was a first contact again, pinned without a word. Fixed
2026-10-27 (owner's design):
  * each account's pins in a sealed store of their own -- apart from the
    identity vault, the X1 server pins and chat history -- sealed by the same
    Rust path as F3 identities, but in its own directory, under its own key
    file;
  * Wipe & Exit destroys it;
  * a record that will not open is refused (`trust_unavailable`), retried,
    never replaced.

Before the fix these tests failed: the first three, by accepting the
changed key after the restart.
"""
from __future__ import annotations

import os
import re
import tempfile

import pytest

import test_smp_end_to_end as E

otr = E.otr
pytest.importorskip("otrv4_core")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ME, PEER = "alice@one.test", "bob@example.test"
IDENT, MLDSA, OTHER_MLDSA = b"\x01" * 57, b"\x02" * 2592, b"\x03" * 2592


@pytest.fixture(autouse=True)
def _own_rate_limiter(monkeypatch):
    monkeypatch.setattr(otr, "_dake1_rate_limiter", otr.DAKE1RateLimiter())


@pytest.fixture
def home(monkeypatch):
    d = tempfile.mkdtemp()
    monkeypatch.setenv("HOME", d)
    return d


class DictVault:
    """The Kotlin `Vault` contract; get answers None for absent (and, like
    KeystoreVault, for a record it cannot open)."""

    def __init__(self):
        self.entries = {}

    def put(self, name, data):
        self.entries[name] = bytes(data)

    def get(self, name):
        return self.entries.get(name)

    def remove(self, name):
        self.entries.pop(name, None)


class Install:
    """One install: its identity vault and trust vault (Android), or its
    files (desktop). `start()` is the app process starting."""

    def __init__(self, kind):
        self.kind = kind
        self.identity_vault, self.trust_vault = DictVault(), DictVault()

    def start(self, transport=None):
        from android_bridge.app import OtrApp
        from android_bridge import account_identity, account_trust
        if transport is not None:
            a = OtrApp(E._manager(), transport)
        else:
            a = OtrApp.__new__(OtrApp)
            a._engine = E._manager()
            a._signed_in = False
            a._wiped = False
        if self.kind == "android":
            a.use_identity_store(account_identity.for_android(self.identity_vault))
            a.use_trust_store(account_trust.for_android(self.trust_vault, True))
        else:
            a.use_identity_store(account_identity.for_desktop())
            a.use_trust_store(account_trust.for_desktop())
        a.bind_identity_account(ME)
        return a


class _Contact:
    """A contact's app over the wire harness; [engine] is their identity."""

    def __init__(self, engine=None):
        self.engine = engine or E._manager()


def _talk(install, contact, queued=None):
    """Alice's app (this install, started now) opens a session with
    [contact], through the bridge as the apps do. [queued]: a line typed
    before the session is up. Returns (alice, contact's app, alice's events,
    what the contact's app received)."""
    import test_deniability_wire_audit as W
    from android_bridge.app import OtrApp
    wire = W.Wire()
    wire.delivered = []
    alice = install.start(transport=W.Link(wire, ME))
    peer = OtrApp(contact.engine, W.Link(wire, PEER))
    events, received = [], []

    class _Sink:
        def __init__(self, into):
            self.on_event = into.append

    alice.set_event_sink(_Sink(events))
    peer.set_event_sink(_Sink(received))
    for app in (alice, peer):
        app.otr_capability = lambda _p: "available"
        app.GROUP_STATE_DIR = os.path.join(tempfile.mkdtemp(), "groups")
    wire.apps.update({ME: alice, PEER: peer})
    if queued is not None:
        alice.send_user_text(PEER, queued)
    alice.ensure_otr(PEER)
    return alice, peer, events, received


def _bodies(events):
    return [getattr(e, "body", None) for e in events if type(e).__name__ == "MessageReceived"]


KINDS = ["android", "desktop"]


# ── the defect, closed ──────────────────────────────────────────────────────

@pytest.mark.parametrize("kind", KINDS)
def test_after_a_restart_a_changed_fingerprint_is_refused(home, kind):
    from android_bridge.events import SecurityState
    install = Install(kind)
    alice, _peer, _ev, _rx = _talk(install, _Contact())
    assert alice.security_state(PEER) is not SecurityState.PLAINTEXT, "first contact pins bob"
    impostor = _Contact()                                    # another identity
    alice, _peer, events, received = _talk(install, impostor, queued="for bob only")
    assert alice.security_state(PEER) is SecurityState.FINGERPRINT_MISMATCH
    changed = [e for e in events if type(e).__name__ == "FingerprintChanged"]
    assert changed and changed[0].stored_fingerprint != changed[0].received_fingerprint
    assert "for bob only" not in _bodies(received), "nothing queued goes to the changed key"


@pytest.mark.parametrize("kind", KINDS)
def test_after_a_restart_the_same_contact_is_still_accepted(home, kind):
    from android_bridge.events import SecurityState
    install = Install(kind)
    bob = _Contact()
    _talk(install, bob)
    bob.engine.clear_all_sessions("restart")
    alice, _peer, events, received = _talk(install, bob, queued="hello again")
    assert alice.security_state(PEER) in (SecurityState.ENCRYPTED, SecurityState.FINGERPRINT)
    assert not [e for e in events if type(e).__name__ == "FingerprintChanged"]
    assert "hello again" in _bodies(received)


def test_within_one_run_a_new_identity_is_caught_too(home):
    """Before P1's fix the apps never checked the pin at all, in a run or
    across runs (the bridge did not call `check_or_pin`): a contact under a
    whole new identity was simply accepted."""
    from android_bridge.events import SecurityState
    install = Install("android")
    alice, _p, _e, _r = _talk(install, _Contact())
    import test_deniability_wire_audit as W
    from android_bridge.app import OtrApp
    alice._engine.clear_all_sessions("the contact went away")
    wire = W.Wire()
    wire.delivered = []
    impostor = OtrApp(E._manager(), W.Link(wire, PEER))
    impostor.otr_capability = lambda _p: "available"
    alice._transport = W.Link(wire, ME)
    wire.apps.update({ME: alice, PEER: impostor})
    alice.ensure_otr(PEER)
    assert alice.security_state(PEER) is SecurityState.FINGERPRINT_MISMATCH


def test_resetting_trust_after_checking_accepts_the_checked_key_only(home):
    from android_bridge.events import SecurityState
    install = Install("android")
    _talk(install, _Contact())
    checked = _Contact()
    alice, _p, _e, _r = _talk(install, checked)
    assert alice.security_state(PEER) is SecurityState.FINGERPRINT_MISMATCH
    assert alice.reset_trust(PEER)
    assert alice.security_state(PEER) is not SecurityState.FINGERPRINT_MISMATCH
    # The key the user checked is pinned at the reset, not whatever the next
    # handshake brings: the checked contact is accepted after a restart ...
    checked.engine.clear_all_sessions("restart")
    alice, _p, events, _r = _talk(install, checked)
    assert alice.security_state(PEER) is not SecurityState.FINGERPRINT_MISMATCH
    assert not [e for e in events if type(e).__name__ == "FingerprintChanged"]
    # ... and a third key is refused like any other change.
    alice, _p, events, _r = _talk(install, _Contact())
    assert alice.security_state(PEER) is SecurityState.FINGERPRINT_MISMATCH


@pytest.mark.parametrize("kind", KINDS)
def test_after_a_restart_a_changed_ml_dsa_key_is_refused(home, kind):
    install = Install(kind)
    install.start()._engine.trust_db.check_or_pin_pq(PEER, IDENT, MLDSA, True)
    db = install.start()._engine.trust_db
    with pytest.raises(otr.TrustDatabase.PqIdentityRefused):
        db.check_or_pin_pq(PEER, IDENT, OTHER_MLDSA, True)
    with pytest.raises(otr.TrustDatabase.PqIdentityRefused):
        db.check_or_pin_pq(PEER, IDENT, None, False)          # dropped: a downgrade


def test_resetting_trust_pins_the_accepted_key_and_sends_what_waited(home):
    from android_bridge.events import SecurityState
    install = Install("android")
    _talk(install, _Contact())
    alice, _p, _e, received = _talk(install, _Contact(), queued="after the check")
    assert alice.security_state(PEER) is SecurityState.FINGERPRINT_MISMATCH
    assert "after the check" not in _bodies(received)
    pq_of_checked = dict(alice._engine.trust_db._db[PEER].get("pq") or {})
    assert pq_of_checked, "the checked handshake pinned its ML-DSA key"
    alice.reset_trust(PEER)
    assert alice.security_state(PEER) is not SecurityState.FINGERPRINT_MISMATCH
    assert "after the check" in _bodies(received), "released once the key was accepted"
    with pytest.raises(otr.TrustDatabase.FingerprintMismatchError):
        alice._engine.trust_db.check_or_pin(PEER, "0" * 64)      # the accepted key is pinned
    # Both halves: the ML-DSA key of the checked session stays pinned too,
    # after a restart, so the next handshake does not fill it.
    assert install.start()._engine.trust_db._db[PEER].get("pq") == pq_of_checked


def test_calls_and_files_are_refused_while_the_key_does_not_match(home):
    """Even with the shared-secret check passed in that session: one gate
    for calls and files, and the mismatch closes both until Reset trust."""
    install = Install("android")
    _talk(install, _Contact())
    alice, _p, _e, _r = _talk(install, _Contact())

    class _Verified:
        def _smp_verified(self, peer):
            return True
    alice.calls._ensure_manager = lambda: _Verified()
    assert alice.files._verified(PEER) is False
    assert alice.call_gate(PEER)["gate"] == "fingerprint_changed"
    alice.reset_trust(PEER)
    assert alice.files._verified(PEER) is True


def test_the_they_match_confirmation_is_kept_with_the_pin(home):
    install = Install("android")
    app = install.start()
    app._engine.trust_db.check_or_pin(PEER, "f" * 64)
    assert app._engine.trust_db.add_trust(PEER, "f" * 64)
    assert install.start()._engine.trust_db.is_trusted(PEER, "f" * 64)


# ── per account, apart, sealed ──────────────────────────────────────────────

def test_pins_are_per_account(home):
    install = Install("android")
    app = install.start()
    app._engine.trust_db.check_or_pin(PEER, "a" * 64)
    app.bind_identity_account("carol@two.test")
    assert app._engine.trust_db.check_or_pin(PEER, "b" * 64) is False, \
        "another account: its own (empty) pins"
    app.bind_identity_account(ME)
    with pytest.raises(otr.TrustDatabase.FingerprintMismatchError):
        app._engine.trust_db.check_or_pin(PEER, "b" * 64)


def test_the_trust_store_is_apart_from_identities_server_pins_and_history(home):
    install = Install("android")
    install.start()._engine.trust_db.check_or_pin(PEER, "a" * 64)
    assert install.trust_vault.entries, "kept in the trust vault"
    assert all(n.startswith("otrv4plus.trust.") for n in install.trust_vault.entries)
    assert not any("trust" in n for n in install.identity_vault.entries)
    from android_bridge import account_identity, account_trust, server_pins
    assert os.path.realpath(account_trust.trust_dir()) != os.path.realpath(account_identity.identity_dir())
    assert "trust" not in getattr(server_pins, "__file__", "")
    assert os.path.exists(os.path.join(account_trust.trust_dir(), "trust.dek"))
    assert not os.path.exists(os.path.join(account_trust.trust_dir(), "identity.dek")), \
        "its own key file"


def test_the_record_is_sealed_names_no_jid_and_is_bound_to_its_account(home):
    install = Install("desktop")
    install.start()._engine.trust_db.check_or_pin(PEER, "c" * 64)
    from android_bridge import account_trust
    d = account_trust.trust_dir()
    records = [f for f in os.listdir(d) if f.endswith(".sealed")]
    assert len(records) == 1 and "alice" not in records[0] and "one.test" not in records[0]
    blob = open(os.path.join(d, records[0]), "rb").read()
    assert b"bob@" not in blob and b"c" * 64 not in blob, "ciphertext only"
    assert os.stat(os.path.join(d, records[0])).st_mode & 0o077 == 0
    # Another account's slot: the record is bound to its name.
    other = account_trust.for_desktop().for_account("carol@two.test")
    open(os.path.join(d, "trust.%s.sealed" % account_trust.trust_tag("carol@two.test")), "wb").write(blob)
    with pytest.raises(account_trust.TrustUnavailable):
        other.load()


# ── a record that will not open ─────────────────────────────────────────────

@pytest.mark.parametrize("damage", ["tampered", "vault_cannot_open"])
def test_an_unopenable_record_is_refused_never_replaced(home, damage):
    from android_bridge.app_base import BridgeError
    install = Install("android")
    install.start()._engine.trust_db.check_or_pin(PEER, "a" * 64)
    [name] = install.trust_vault.entries
    if damage == "tampered":
        install.trust_vault.entries[name] = b"\x01" + b"\x00" * 80
    else:
        del install.trust_vault.entries[name]      # KeystoreVault: None, record unreadable
    kept = dict(install.trust_vault.entries)
    for _attempt in range(2):                      # retried: refused again, not reset
        with pytest.raises(BridgeError) as err:
            install.start()
        assert err.value.code == "trust_unavailable"
    assert install.trust_vault.entries == kept, "nothing replaced"


def test_a_pin_that_cannot_be_kept_fails_the_check_and_is_retried(home):
    install = Install("desktop")
    db = install.start()._engine.trust_db
    real = db._store.save
    db._store.save = lambda snapshot: (_ for _ in ()).throw(OSError("disk full"))
    with pytest.raises(Exception):
        db.check_or_pin(PEER, "d" * 64)
    db._store.save = real
    db.check_or_pin(PEER, "d" * 64)                # retried, now kept
    with pytest.raises(otr.TrustDatabase.FingerprintMismatchError):
        install.start()._engine.trust_db.check_or_pin(PEER, "e" * 64)


# ── Wipe & Exit ─────────────────────────────────────────────────────────────

@pytest.mark.parametrize("kind", KINDS)
def test_wipe_and_exit_destroys_the_trust_store(home, kind):
    install = Install(kind)
    install.start()._engine.trust_db.check_or_pin(PEER, "a" * 64)
    from android_bridge import account_trust, wipe
    d = os.path.realpath(account_trust.trust_dir())
    roots = [os.path.realpath(r) for r in wipe.python_state_roots()]
    assert any(d.startswith(r + os.sep) for r in roots), "under a root Wipe & Exit destroys"
    wipe.wipe_disk()
    assert not os.path.exists(d), "the trust directory, its key file and markers are gone"
    if kind == "android":
        install.trust_vault.entries.clear()         # KeystoreVault.destroy: key and sections
        install.identity_vault.entries.clear()
    app = install.start()                           # a relaunch starts empty
    assert app._engine.trust_db.check_or_pin(PEER, "b" * 64) is False


def test_android_destroys_the_trust_section_with_the_key():
    src = open(os.path.join(ROOT, "android/app/src/main/java/org/otrv4plus/android/"
                            "security/KeystoreVault.kt"), encoding="utf-8").read()
    assert re.search(r'const val TRUST = "trust-vault"', src)
    assert re.search(r"private val SECTIONS = setOf\(DEFAULT, IDENTITY, TRUST\)", src)
    destroy = src[src.index("fun destroy(context: Context)"):]
    destroy = destroy[:destroy.index("return keyGone")]
    assert destroy.index("deleteEntry(ALIAS)") < destroy.index("for (section in SECTIONS)")


# ── wiring, and the residual where the Keystore does not work ───────────────

def test_android_passes_its_own_trust_vault_and_whether_it_keeps_records():
    src = open(os.path.join(ROOT, "android/app/src/main/java/org/otrv4plus/android/"
                            "bridge/ChaquopyOtrCore.kt"), encoding="utf-8").read()
    call = src[src.index("KeystoreVault.open(appContext, KeystoreVault.TRUST)"):]
    call = call[:call.index("\n            }")]
    assert '"use_trust_store"' in call and '"for_android", trust, trust is KeystoreVault' in call


def test_the_desktop_host_keeps_trust(home, monkeypatch):
    from android_bridge import bootstrap
    from desktop_bridge import host
    monkeypatch.setattr(bootstrap, "ensure_runtime", lambda: None)
    monkeypatch.setattr(bootstrap, "load_orchestration", lambda: otr)
    assert getattr(host._real_app(), "_trust_store", None) is not None


def test_residual_without_a_working_keystore_the_pins_last_one_run(home):
    from android_bridge import account_trust
    assert account_trust.for_android(DictVault(), False) is None
    from android_bridge.app import OtrApp
    a = OtrApp.__new__(OtrApp)
    a._engine, a._signed_in, a._wiped = E._manager(), False, False
    a.use_trust_store(None)
    a.bind_identity_account(ME)
    a._engine.trust_db.check_or_pin(PEER, "a" * 64)
    b = OtrApp.__new__(OtrApp)
    b._engine, b._signed_in, b._wiped = E._manager(), False, False
    b.use_trust_store(None)
    b.bind_identity_account(ME)
    assert b._engine.trust_db.check_or_pin(PEER, "b" * 64) is False, "a first contact again"


def test_the_terminal_keeps_its_pins_across_restarts_as_before():
    src = open(os.path.join(ROOT, "client", "otrv4plus_xmpp.py"), encoding="utf-8").read()
    assert "persist_trust=True," in src
    path = os.path.join(tempfile.mkdtemp(), "trust.json")
    otr.TrustDatabase(path, persistent=True).check_or_pin(PEER, "a" * 64)
    with pytest.raises(otr.TrustDatabase.FingerprintMismatchError):
        otr.TrustDatabase(path, persistent=True).check_or_pin(PEER, "b" * 64)


def test_a_marker_whose_record_is_gone_is_refused_until_the_user_forgets_it(home):
    """The handset state of 2026-10-27: Create account answered "This
    account's saved contact keys on this device would not open" -- a marker
    naming a record the vault no longer opens (its key or its records gone,
    the marker kept: a wipe cut short, or two keys made at once). Refused
    every time, never replaced; the user can discard it, and only then is
    the account usable again, every contact a first contact."""
    from android_bridge.app_base import BridgeError
    from android_bridge.trace import TRACE
    from android_bridge import connection as C
    install = Install("android")
    _talk(install, _Contact())                       # a pin: record + marker
    install.trust_vault = DictVault()                # the vault cannot open it now
    TRACE.clear()
    for _ in range(2):
        with pytest.raises(BridgeError) as refused:
            install.start()
        assert refused.value.code == "trust_unavailable"
    events = [ev for ev in TRACE.events() if ev["event"] == "trust_unavailable"]
    assert events and events[-1]["fields"].get("reason") == "marker_without_record"
    # What Kotlin sees: Log in answers the code, nothing raises. (Create
    # account is not stopped by it: registration uses no pins.)
    from android_bridge.app import OtrApp
    from android_bridge import account_identity, account_trust
    a = OtrApp.__new__(OtrApp)
    a._engine, a._signed_in, a._wiped = E._manager(), False, False
    a.use_identity_store(account_identity.for_android(install.identity_vault))
    a.use_trust_store(account_trust.for_android(install.trust_vault, True))
    assert C.controller_for(a, ME, "", "127.0.0.1", 1).connect("pw")["code"] == "trust_unavailable"
    # The user's deliberate answer.
    assert a.forget_account_trust(ME) is True
    a.bind_identity_account(ME)
    assert a._engine.trust_db.list_trusted() == {}
    assert install.start()._engine.trust_db.check_or_pin(PEER, "A1" * 56) is False


def test_forget_says_in_the_trace_why_it_did_not(home):
    """Device report, 2026-10-27: "something went wrong" on Forget saved
    contact keys, with nothing to say why. Each outcome is traced."""
    from android_bridge.app import OtrApp
    from android_bridge import account_trust
    from android_bridge.trace import TRACE

    def last():
        return [ev["fields"]["outcome"] for ev in TRACE.events()
                if ev["event"] == "forget_trust"][-1]

    a = OtrApp.__new__(OtrApp)
    a._engine, a._signed_in, a._wiped = E._manager(), False, False
    assert a.forget_account_trust(ME) is False and last() == "no_trust_store"
    a.use_trust_store(account_trust.for_android(DictVault(), True))
    assert a.forget_account_trust("charliebrown") is False and last() == "not_an_account"
    assert a.forget_account_trust(ME) is True and last() == "forgotten"

    class Broken(DictVault):
        def remove(self, name):
            raise OSError("read-only")
    a.use_trust_store(account_trust.for_android(Broken(), True))
    assert a.forget_account_trust(ME) is False and last() == "raised"
    assert [ev["fields"].get("error") for ev in TRACE.events()
            if ev["event"] == "forget_trust"][-1] == "OSError"


def test_wipe_crypto_removes_the_trust_markers_before_the_vault_is_destroyed(home):
    install = Install("android")
    alice, _p, _e, _r = _talk(install, _Contact())
    trust = os.path.join(home, ".otrv4plus", "trust")
    assert any(f.endswith(".present") for f in os.listdir(trust))
    alice.wipe_crypto()
    assert not os.path.exists(trust), "a wipe cut short after this left markers behind"


class _Created:
    """Stands in for XmppTransport: the server answers [answer]."""
    answer = ("ok", "The account was created.")

    def __init__(self, profile, password, **kw):
        pass

    def register_account(self):
        return type(self).answer

    def close(self):
        pass


def _android_app(install):
    from android_bridge.app import OtrApp
    from android_bridge import account_identity, account_trust
    a = OtrApp.__new__(OtrApp)
    a._engine, a._signed_in, a._wiped = E._manager(), False, False
    a.use_identity_store(account_identity.for_android(install.identity_vault))
    a.use_trust_store(account_trust.for_android(install.trust_vault, True))
    return a


def _create(app, answer=("ok", "The account was created.")):
    from android_bridge import connection as C
    _Created.answer = answer
    ctl = C.controller_for(app, ME, "127.0.0.1")
    ctl._transport_factory = _Created
    return ctl, ctl.register("correct horse battery staple 9")


def test_create_account_clears_stale_unopenable_keys_and_signs_in(home):
    """Owner, 2026-10-27: after a successful Create account the server has
    confirmed the username was free, so keys saved under it are an earlier
    account's. Discarded at once, a notice said, and the sign-in that follows
    is not stopped: no refusal, so no Forget button."""
    from android_bridge import connection as C
    install = Install("android")
    _talk(install, _Contact())
    install.trust_vault = DictVault()                # unopenable now
    a = _android_app(install)
    ctl, result = _create(a)
    assert result["ok"] is True
    assert result["notice"] == C.STALE_TRUST_NOTICE
    assert ctl._refused is None, "the sign-in on this controller is not refused"
    assert C.controller_for(a, ME, "127.0.0.1")._refused is None, "nor on a new one"
    a.bind_identity_account(ME)
    assert a._engine.trust_db.list_trusted() == {}


def test_create_account_clears_stale_readable_keys_too(home):
    from android_bridge import connection as C
    install = Install("android")
    _talk(install, _Contact())                       # pins that open
    _ctl, result = _create(_android_app(install))
    assert result["notice"] == C.STALE_TRUST_NOTICE
    assert install.start()._engine.trust_db.list_trusted() == {}


def test_a_refused_create_account_discards_nothing_and_sign_in_stays_refused(home):
    from android_bridge.app_base import BridgeError
    install = Install("android")
    _talk(install, _Contact())
    install.trust_vault = DictVault()
    a = _android_app(install)
    ctl, result = _create(a, ("conflict", "That username is already taken."))
    assert result["ok"] is False and "notice" not in result
    assert ctl.connect("pw")["code"] == "trust_unavailable"
    with pytest.raises(BridgeError):
        install.start()


def test_a_new_name_with_nothing_saved_says_nothing(home):
    _ctl, result = _create(_android_app(Install("android")))
    assert result["ok"] is True and "notice" not in result


def test_the_stale_discard_runs_only_after_a_confirmed_create_account():
    import glob
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    users = set()
    for path in glob.glob(os.path.join(root, "*_bridge", "*.py")) + \
            glob.glob(os.path.join(root, "client", "*.py")) + \
            glob.glob(os.path.join(root, "android", "app", "src", "main", "java", "**", "*.kt"),
                      recursive=True):
        if os.path.islink(path):
            continue
        src = open(path, encoding="utf-8").read()
        if "discard_stale_account_trust" in src or "_after_account_created" in src:
            users.add(os.path.basename(path))
    # Defined in app_smp.py; reached from connection.py alone.
    assert users == {"app_smp.py", "connection.py"}, users
    src = open(os.path.join(root, "android_bridge", "connection.py"), encoding="utf-8").read()
    assert 'notice = self._after_account_created() if ok else ""' in src
