# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""F2 -- one identity per account, so accounts cannot be linked by their key.

The residual U1 left: the long-term identity (Ed448 + ML-DSA) belonged to the
PROCESS on Android and desktop and to the MACHINE in the terminal client, so
two accounts used one after the other presented the same key -- and that key
travels in every DAKE1, in a message body the XMPP server relays and can
read. A fingerprint derived from (key, username) for display would have
changed only the string compared; the server and every peer would still see
the same raw key. So the fix is the key itself (SPEC §3.1):

  * engines whose identity is not persisted get a NEW identity, from the same
    generation code, when the account changes -- before anything is sent as
    the new account; the old handles are zeroized in Rust;
  * the terminal keeps one sealed record per account.

Key generation and sealing are unchanged.
"""
import os
import tempfile

import pytest

import test_smp_end_to_end as E

otr = E.otr
PEER = "peer@example.test"


@pytest.fixture(autouse=True)
def _own_rate_limiter(monkeypatch):
    monkeypatch.setattr(otr, "_dake1_rate_limiter", otr.DAKE1RateLimiter())


def _app():
    from android_bridge.app import OtrApp
    a = OtrApp.__new__(OtrApp)
    a._engine = E._manager()
    a._signed_in = False
    a._wiped = False
    return a


def _dake(mgr, me, peer_mgr, peer):
    first, _ = mgr.handle_outgoing_message(peer, "")
    E._relay(first, mgr, peer_mgr, me, peer)
    assert peer_mgr.has_encrypted_session(me)
    return peer_mgr.get_session(me).get_fingerprint()        # what the PEER saw


# ── the engine ──────────────────────────────────────────────────────────────

class TestRotation:
    def test_a_new_identity_with_a_new_fingerprint(self):
        m = E._manager()
        before = m.get_fingerprint()
        after = m.rotate_identity("test")
        assert after and after != before and m.get_fingerprint() == after

    def test_the_old_handles_are_zeroized(self):
        m = E._manager()
        old = m.client_profile
        handles = [getattr(old, n) for n in ("identity_key", "prekey") if getattr(old, n, None)]
        m.rotate_identity("test")
        assert handles
        for h in handles:
            assert h.destroyed
        with pytest.raises(RuntimeError, match="destroyed"):
            old.identity_key.sign(b"anything")

    def test_sessions_and_pins_of_the_old_identity_go(self):
        a, b = E._manager(), E._manager()
        _dake(a, "a@example.test", b, PEER)
        assert a.has_encrypted_session(PEER)
        a.rotate_identity("account changed")
        assert not a.sessions and not a.has_encrypted_session(PEER)
        assert not a.trust_db._db, "in-memory pins of the previous account went too"
        assert a.take_final_revelations(), "ended deniably (L1)"

    def test_a_persisted_identity_is_never_rotated(self):
        m = E._manager()
        m.config.persist_identity = True
        with pytest.raises(RuntimeError):
            m.rotate_identity("test")


# ── on the wire: what a peer (and the server) sees ──────────────────────────

class TestUnlinkableOnTheWire:
    def test_two_accounts_in_one_process_present_different_keys(self):
        """The linking vector itself: the key in DAKE1."""
        app = _app()
        assert app.bind_identity_account("alice@one.test") is False   # start-up identity
        peer = E._manager()
        seen_as_alice = _dake(app._engine, "alice@one.test", peer, PEER)
        app._engine.clear_all_sessions("sign out")
        assert app.bind_identity_account("bob@two.test") is True
        peer2 = E._manager()
        seen_as_bob = _dake(app._engine, "bob@two.test", peer2, PEER)
        assert seen_as_alice and seen_as_bob and seen_as_alice != seen_as_bob

    def test_same_account_on_two_devices_has_two_keys(self):
        one, two = _app(), _app()
        one.bind_identity_account("alice@one.test")
        two.bind_identity_account("alice@one.test")
        one.note_signed_in("alice@one.test")
        two.note_signed_in("alice@one.test")
        assert one.local_fingerprint() != two.local_fingerprint()


# ── the bridge: when it happens ─────────────────────────────────────────────

class TestTheAccountBoundary:
    def test_the_same_account_again_keeps_its_identity(self):
        app = _app()
        app.bind_identity_account("alice@one.test")
        fp = app._engine.get_fingerprint()
        assert app.bind_identity_account("Alice@One.test/phone") is False
        assert app._engine.get_fingerprint() == fp

    def test_a_switch_hides_the_old_fingerprint_until_the_new_login(self):
        app = _app()
        app.bind_identity_account("alice@one.test")
        app.note_signed_in("alice@one.test")
        old = app.local_fingerprint()
        assert old
        app.bind_identity_account("bob@two.test")
        assert app.local_fingerprint() == "", "nothing until bob's own login"
        app.note_signed_in("bob@two.test")
        assert app.local_fingerprint() not in ("", old)

    def test_nothing_that_is_not_an_account_rotates_anything(self):
        app = _app()
        fp = app._engine.get_fingerprint()
        for junk in ("", "nobody", "/res"):
            assert app.bind_identity_account(junk) is False
        assert app._engine.get_fingerprint() == fp

    def test_every_connection_binds_before_anything_is_sent(self):
        from android_bridge import connection as C
        calls = []

        class _App:
            def bind_identity_account(self, jid):
                calls.append(jid)

        ctl = C.controller_for(_App(), jid="carol@example.i2p")
        assert calls == ["carol@example.i2p"]
        assert ctl is not None
        src = open(C.__file__, encoding="utf-8").read()
        fn = src[src.index("def controller_for("):src.index("def _follow_sam_udp_port(")]
        assert fn.index("bind(jid)") < fn.index("return ConnectionController(app, profile)")


# ── the terminal: one sealed record per account ─────────────────────────────

class TestTerminalRecords:
    @pytest.fixture
    def xmpp(self, monkeypatch):
        x = pytest.importorskip("otrv4plus_xmpp")
        monkeypatch.setattr(x._host, "XMPP_STATE_DIR", tempfile.mkdtemp())
        return x

    def test_each_account_has_its_own_record_named_by_hash(self, xmpp):
        a = xmpp._identity_path_for("alice@one.test")
        b = xmpp._identity_path_for("bob@two.test")
        assert a != b
        for path, name in ((a, "alice"), (b, "bob")):
            assert name not in os.path.basename(path), "no JID in a file name"
        assert xmpp._identity_path_for("Alice@One.test/laptop") == a

    def test_the_old_record_is_kept_by_the_first_account_only(self, xmpp):
        legacy = xmpp._host._xmpp_state_path("identity.sealed")
        for suffix in ("", ".mldsa"):
            with open(legacy + suffix, "wb") as fh:
                fh.write(b"sealed" + suffix.encode())
        a = xmpp._identity_path_for("alice@one.test")
        assert open(a, "rb").read() == b"sealed" and open(a + ".mldsa", "rb").read() == b"sealed.mldsa"
        assert not os.path.exists(legacy)
        b = xmpp._identity_path_for("bob@two.test")
        assert not os.path.exists(b), "a second account starts fresh"

    def test_two_accounts_load_two_real_identities(self, xmpp):
        fps = []
        for account in ("alice@one.test", "bob@two.test", "alice@one.test"):
            cfg = xmpp._xmpp_otr_config(account)
            for name in ("trust_db_path", "smp_secrets_path"):
                setattr(cfg, name, os.path.join(tempfile.mkdtemp(), name))
            fps.append(otr.EnhancedSessionManager(config=cfg).get_fingerprint())
        assert fps[0] != fps[1], "two accounts, two keys"
        assert fps[0] == fps[2], "the same account keeps its key across runs"

    def test_no_account_no_persistent_identity(self, xmpp):
        with pytest.raises(ValueError):
            xmpp._identity_path_for("")

    def test_the_client_opens_the_record_of_the_account_it_signs_in_as(self, xmpp, monkeypatch):
        """The terminal client asks for the identity of its own bare JID."""
        seen = []

        class _Stop(Exception):
            pass

        def _config(account=""):
            seen.append(account)
            raise _Stop

        monkeypatch.setattr(xmpp, "_xmpp_otr_config", _config)
        client = xmpp.OTRv4PlusXMPP.__new__(xmpp.OTRv4PlusXMPP)
        from slixmpp import JID
        client.boundjid = JID("Alice@One.test/laptop")
        with pytest.raises(_Stop):
            client._init_engine(False)
        assert seen == ["alice@one.test"]
