#!/usr/bin/env python3
"""XMPP persistent identity, IRC ephemerality, and TOFU trust.

The invariant these tests exist to protect is a split, not a feature:

    XMPP  persistent Ed448 identity + persistent pinned trust
    IRC   fresh identity every run  + nothing written to disk

Before this split both protocols shared ~/.otrv4plus/trust.json while both
regenerated their identity every launch. The result was not "TOFU that did
nothing": `add_trust` raises FingerprintMismatchError when the stored value
differs, so every reconnect with a previously trusted peer printed "This may
indicate a MITM attack". The tests below pin the behaviour that replaced it.
"""

import os
import sys
import tempfile

import pytest

from textwrap import dedent as textwrap_dedent

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

otr = pytest.importorskip("otrv4_")
ident = pytest.importorskip("otrv4plus_identity")


@pytest.fixture
def statedir():
    with tempfile.TemporaryDirectory() as d:
        yield d


def _paths(d):
    return os.path.join(d, "identity.sealed"), os.path.join(d, ".identity_dek")


# ---------------------------------------------------------------------------
# XMPP identity persistence
# ---------------------------------------------------------------------------

class TestXmppIdentityPersists:

    def test_first_run_creates_an_identity(self, statedir):
        rec, dek = _paths(statedir)
        _e, _x, pub = ident.load_or_create_identity(rec, dek)
        assert len(pub) == 57
        assert os.path.exists(rec) and os.path.exists(dek)

    def test_the_same_identity_comes_back_on_the_next_run(self, statedir):
        rec, dek = _paths(statedir)
        _e1, _x1, first = ident.load_or_create_identity(rec, dek)
        _e2, _x2, second = ident.load_or_create_identity(rec, dek)
        assert first == second, "XMPP identity did not survive a restart"

    def test_it_survives_many_restarts(self, statedir):
        rec, dek = _paths(statedir)
        seen = {ident.load_or_create_identity(rec, dek)[2] for _ in range(5)}
        assert len(seen) == 1

    def test_the_record_and_key_are_owner_only(self, statedir):
        rec, dek = _paths(statedir)
        ident.load_or_create_identity(rec, dek)
        for path in (rec, dek):
            mode = os.stat(path).st_mode & 0o777
            assert mode == 0o600, "%s is %o" % (path, mode)

    def test_the_seed_is_not_reachable_from_python(self):
        # The whole reason persistence goes through Rust. If a seed accessor
        # ever appears, persisting the identity stops being safe and this
        # module's design premise is gone.
        core = pytest.importorskip("otrv4_core")
        seedish = [n for n in dir(core)
                   if "seed" in n.lower() and not n.startswith("_")]
        assert seedish == [], "seed-shaped accessor appeared: %s" % seedish


class TestCorruptIdentityFailsClosed:

    def test_a_tampered_record_raises(self, statedir):
        rec, dek = _paths(statedir)
        ident.load_or_create_identity(rec, dek)
        with open(rec, "r+b") as fh:
            fh.seek(20)
            fh.write(b"\xff\xff\xff\xff")
        with pytest.raises(ident.IdentityUnavailable):
            ident.load_or_create_identity(rec, dek)

    def test_a_tampered_record_is_not_replaced(self, statedir):
        # Silently regenerating would change our fingerprint with no signal,
        # and every peer holding a pin would see the identity change that TOFU
        # exists to report -- caused by us, reported as an attack.
        rec, dek = _paths(statedir)
        ident.load_or_create_identity(rec, dek)
        with open(rec, "r+b") as fh:
            fh.seek(20)
            fh.write(b"\xff\xff\xff\xff")
        before = open(rec, "rb").read()
        with pytest.raises(ident.IdentityUnavailable):
            ident.load_or_create_identity(rec, dek)
        assert open(rec, "rb").read() == before

    def test_a_truncated_record_raises(self, statedir):
        rec, dek = _paths(statedir)
        ident.load_or_create_identity(rec, dek)
        blob = open(rec, "rb").read()
        with open(rec, "wb") as fh:
            fh.write(blob[:len(blob) // 2])
        with pytest.raises(ident.IdentityUnavailable):
            ident.load_or_create_identity(rec, dek)

    def test_a_lost_key_file_does_not_silently_mint_a_new_identity(self, statedir):
        rec, dek = _paths(statedir)
        ident.load_or_create_identity(rec, dek)
        os.unlink(dek)
        with pytest.raises(ident.IdentityUnavailable):
            ident.load_or_create_identity(rec, dek)

    def test_a_truncated_key_file_is_refused_not_regenerated(self, statedir):
        # Regenerating the key would make the identity permanently unopenable
        # while looking like a clean first run.
        rec, dek = _paths(statedir)
        ident.load_or_create_identity(rec, dek)
        with open(dek, "wb") as fh:
            fh.write(b"short")
        with pytest.raises(ident.IdentityUnavailable):
            ident.load_or_create_identity(rec, dek)
        assert open(dek, "rb").read() == b"short", "the key file was replaced"

    def test_no_path_configured_raises(self):
        with pytest.raises(ident.IdentityUnavailable):
            ident.load_or_create_identity("", "")


# ---------------------------------------------------------------------------
# The protocol split
# ---------------------------------------------------------------------------

class TestIrcStaysEphemeral:

    def test_the_default_config_persists_nothing(self):
        cfg = otr.OTRConfig()
        assert cfg.persist_identity is False
        assert cfg.persist_trust is False

    def test_a_default_manager_makes_a_fresh_identity_each_time(self, statedir):
        a = otr.EnhancedSessionManager(
            config=otr.OTRConfig(test_mode=True,
                                 trust_db_path=os.path.join(statedir, "a.json")))
        b = otr.EnhancedSessionManager(
            config=otr.OTRConfig(test_mode=True,
                                 trust_db_path=os.path.join(statedir, "b.json")))
        assert a.client_profile.identity_key.public_bytes() \
            != b.client_profile.identity_key.public_bytes()
        assert a.identity_is_persistent is False

    def test_an_ephemeral_manager_writes_no_trust_file(self, statedir):
        path = os.path.join(statedir, "trust.json")
        mgr = otr.EnhancedSessionManager(
            config=otr.OTRConfig(test_mode=True, trust_db_path=path))
        mgr.trust_db.add_trust("alice", "AAAA")
        assert not os.path.exists(path), "IRC mode wrote a persistent trust record"

    def test_an_ephemeral_trust_answer_still_holds_for_the_session(self, statedir):
        db = otr.TrustDatabase(os.path.join(statedir, "t.json"), persistent=False)
        db.add_trust("alice", "AAAA")
        assert db.is_trusted("alice", "AAAA") is True

    def test_ephemeral_mode_does_not_even_read_an_existing_file(self, statedir):
        """Not writing is half of it. Reading would be a leak in the other
        direction: an IRC session would inherit fingerprints pinned by XMPP,
        and a nick that happened to match a JID would arrive pre-trusted.
        """
        path = os.path.join(statedir, "trust.json")
        otr.TrustDatabase(path, persistent=True).add_trust("alice", "AAAA")
        assert os.path.exists(path)
        ephemeral = otr.TrustDatabase(path, persistent=False)
        assert ephemeral.is_trusted("alice", "AAAA") is False
        assert ephemeral.check_or_pin("alice", "AAAA") is False, (
            "the ephemeral store loaded pins written by the persistent one")

    def test_nothing_survives_the_process_in_ephemeral_mode(self, statedir):
        path = os.path.join(statedir, "t.json")
        otr.TrustDatabase(path, persistent=False).add_trust("alice", "AAAA")
        assert otr.TrustDatabase(path, persistent=False).is_trusted("alice", "AAAA") \
            is False

    def test_irc_never_imports_the_persistence_module(self):
        """Behavioural, not textual: build an ephemeral manager in a clean
        interpreter and check the module was never loaded.

        The import sits inside the persist_identity branch so that IRC does not
        merely decline to *use* persistence -- it never loads the code. A
        grep-style assertion would pass on a module-level import guarded by a
        flag, which is exactly the arrangement this forbids.
        """
        import subprocess, textwrap
        prog = textwrap.dedent("""
            import sys, tempfile, os
            sys.path.insert(0, %r)
            import otrv4_ as otr
            d = tempfile.mkdtemp()
            mgr = otr.EnhancedSessionManager(
                config=otr.OTRConfig(test_mode=True,
                                     trust_db_path=os.path.join(d, "t.json")))
            assert mgr.identity_is_persistent is False
            print("LOADED" if "otrv4plus_identity" in sys.modules else "CLEAN")
        """) % os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        out = subprocess.run([sys.executable, "-c", prog],
                             capture_output=True, text=True)
        assert out.returncode == 0, out.stderr[-2000:]
        assert out.stdout.strip() == "CLEAN", (
            "the ephemeral path loaded otrv4plus_identity")


class TestXmppAndIrcStoresAreSeparate:

    def test_the_xmpp_client_uses_its_own_paths(self):
        xmpp = pytest.importorskip("otrv4plus_xmpp")
        cfg = xmpp._xmpp_otr_config()
        legacy = os.path.expanduser("~/.otrv4plus")
        for path in (cfg.trust_db_path, cfg.smp_secrets_path,
                     cfg.identity_path, cfg.identity_dek_path):
            assert path, "XMPP config left a state path unset"
            assert os.path.dirname(path.rstrip("/")) != legacy, (
                "%s is still in the shared directory" % path)

    def test_the_xmpp_client_asks_for_persistence(self):
        xmpp = pytest.importorskip("otrv4plus_xmpp")
        cfg = xmpp._xmpp_otr_config()
        assert cfg.persist_identity is True
        assert cfg.persist_trust is True

    def test_an_irc_write_cannot_reach_the_xmpp_trust_store(self, statedir):
        xmpp_store = os.path.join(statedir, "xmpp", "trust.json")
        os.makedirs(os.path.dirname(xmpp_store))
        otr.TrustDatabase(xmpp_store, persistent=True).add_trust("bob@x", "BBBB")

        irc = otr.EnhancedSessionManager(
            config=otr.OTRConfig(test_mode=True,
                                 trust_db_path=os.path.join(statedir, "irc.json")))
        irc.trust_db.add_trust("bob@x", "CCCC")

        fresh = otr.TrustDatabase(xmpp_store, persistent=True)
        assert fresh.is_trusted("bob@x", "BBBB") is True
        assert fresh.is_trusted("bob@x", "CCCC") is False


# ---------------------------------------------------------------------------
# TOFU
# ---------------------------------------------------------------------------

class TestTofu:

    def _db(self, statedir):
        return otr.TrustDatabase(os.path.join(statedir, "trust.json"),
                                 persistent=True)

    def test_first_contact_is_not_trusted_and_asks(self, statedir):
        assert self._db(statedir).check_or_pin("alice@x", "AAAA") is False

    def test_an_approved_pin_is_trusted_afterwards(self, statedir):
        db = self._db(statedir)
        db.check_or_pin("alice@x", "AAAA")
        db.add_trust("alice@x", "AAAA")
        assert db.check_or_pin("alice@x", "AAAA") is True

    def test_a_pin_survives_a_restart(self, statedir):
        db = self._db(statedir)
        db.add_trust("alice@x", "AAAA")
        assert self._db(statedir).check_or_pin("alice@x", "AAAA") is True

    def test_reconnecting_with_the_same_key_never_warns(self, statedir):
        # The bug this replaced: every reconnect raised a MITM error.
        db = self._db(statedir)
        db.add_trust("alice@x", "AAAA")
        for _ in range(5):
            assert self._db(statedir).check_or_pin("alice@x", "AAAA") is True

    def test_a_changed_fingerprint_raises(self, statedir):
        db = self._db(statedir)
        db.add_trust("alice@x", "AAAA")
        with pytest.raises(otr.TrustDatabase.FingerprintMismatchError):
            db.check_or_pin("alice@x", "BBBB")

    def test_a_changed_fingerprint_does_not_overwrite_the_pin(self, statedir):
        db = self._db(statedir)
        db.add_trust("alice@x", "AAAA")
        with pytest.raises(otr.TrustDatabase.FingerprintMismatchError):
            db.check_or_pin("alice@x", "BBBB")
        with pytest.raises(otr.TrustDatabase.FingerprintMismatchError):
            db.add_trust("alice@x", "BBBB")
        assert self._db(statedir).check_or_pin("alice@x", "AAAA") is True

    def test_clearing_a_pin_is_deliberate_and_works(self, statedir):
        db = self._db(statedir)
        db.add_trust("alice@x", "AAAA")
        assert db.remove_trust("alice@x") is True
        assert db.check_or_pin("alice@x", "BBBB") is False

    def test_declining_the_pin_leaves_it_untrusted(self, statedir):
        db = self._db(statedir)
        db.check_or_pin("alice@x", "AAAA")      # first contact, user says n
        assert db.is_trusted("alice@x", "AAAA") is False
        assert db.check_or_pin("alice@x", "AAAA") is False


class _FakeOtr:
    def __init__(self, db):
        self.trust_db = db

    def trust_fingerprint(self, peer, fp):
        return self.trust_db.add_trust(peer, fp)


class _FakeClient:
    """The smallest object `_apply_tofu` can run against.

    Driving the real method matters here: the TrustDatabase refuses a mismatch
    on its own, but the question these tests ask is whether the *client* takes
    no for an answer -- a handler that caught the exception and repinned would
    leave every TrustDatabase test passing.
    """

    def __init__(self, db):
        self.otr = _FakeOtr(db)
        self._fingerprint_changed = {}
        self._pending = {}
        self.prompted = []
        self.printed = []

    def _prompt_smp_secret(self, peer):
        self.prompted.append(peer)


def _run_tofu(client, peer, fp, monkeypatch):
    xmpp = pytest.importorskip("otrv4plus_xmpp")
    monkeypatch.setattr("builtins.print",
                        lambda *a, **k: client.printed.append(" ".join(map(str, a))))
    xmpp.OTRv4PlusXMPP._apply_tofu(client, peer, fp)


class TestTheClientRefusesAChangedFingerprint:

    def _db(self, statedir):
        return otr.TrustDatabase(os.path.join(statedir, "trust.json"),
                                 persistent=True)

    def test_first_contact_pins_without_asking(self, statedir, monkeypatch):
        """No prompt on first contact, by design.

        Asked to approve a fingerprint never seen before there is nothing to
        check it against, so the only available answer is yes -- and a question
        whose answer is always yes trains the reflex that makes the question
        that DOES matter useless.
        """
        db = self._db(statedir)
        c = _FakeClient(db)
        _run_tofu(c, "alice@x", "AAAA", monkeypatch)
        assert c._pending.get("alice@x") is None, "a prompt was armed"
        assert c._fingerprint_changed == {}
        assert self._db(statedir).check_or_pin("alice@x", "AAAA") is True, (
            "first contact did not pin the fingerprint")

    def test_first_contact_moves_straight_on_to_smp(self, statedir, monkeypatch):
        db = self._db(statedir)
        c = _FakeClient(db)
        _run_tofu(c, "alice@x", "AAAA", monkeypatch)
        assert c.prompted == ["alice@x"]

    def test_the_pin_survives_into_the_next_session(self, statedir, monkeypatch):
        db = self._db(statedir)
        c1 = _FakeClient(db)
        _run_tofu(c1, "alice@x", "AAAA", monkeypatch)
        c2 = _FakeClient(self._db(statedir))
        _run_tofu(c2, "alice@x", "AAAA", monkeypatch)
        assert "matches the pinned identity" in "\n".join(c2.printed)

    def test_there_is_no_prompt_state_left_to_arm(self, statedir):
        """The y/n path is gone, not merely unused.

        Dead code that can still consume the next line typed is worse than no
        code: it is a capture the user cannot see and nothing exercises.
        """
        import inspect
        xmpp = pytest.importorskip("otrv4plus_xmpp")
        src = inspect.getsource(xmpp.OTRv4PlusXMPP)
        assert '_pending[peer] = "trust"' not in src
        assert "_handle_trust_answer" not in src
        feed = inspect.getsource(xmpp.OTRv4PlusXMPP.feed_pending)
        assert '"trust"' not in feed

    def test_a_matching_pin_asks_nothing(self, statedir, monkeypatch):
        db = self._db(statedir)
        db.add_trust("alice@x", "AAAA")
        c = _FakeClient(db)
        _run_tofu(c, "alice@x", "AAAA", monkeypatch)
        assert c._pending.get("alice@x") is None
        assert c.prompted == ["alice@x"], "the SMP step was skipped"

    def test_a_changed_fingerprint_does_not_repin(self, statedir, monkeypatch):
        db = self._db(statedir)
        db.add_trust("alice@x", "AAAA")
        c = _FakeClient(db)
        _run_tofu(c, "alice@x", "BBBB", monkeypatch)
        fresh = self._db(statedir)
        assert fresh.check_or_pin("alice@x", "AAAA") is True, (
            "the client replaced the pinned fingerprint")
        assert fresh.is_trusted("alice@x", "BBBB") is False

    def test_a_changed_fingerprint_offers_no_yes_prompt(self, statedir, monkeypatch):
        # A prompt answerable with `y` is a prompt that gets answered `y`.
        db = self._db(statedir)
        db.add_trust("alice@x", "AAAA")
        c = _FakeClient(db)
        _run_tofu(c, "alice@x", "BBBB", monkeypatch)
        assert c._pending.get("alice@x") is None, (
            "a changed identity can be accepted with the ordinary y keystroke")

    def test_a_changed_fingerprint_records_the_block(self, statedir, monkeypatch):
        db = self._db(statedir)
        db.add_trust("alice@x", "AAAA")
        c = _FakeClient(db)
        _run_tofu(c, "alice@x", "BBBB", monkeypatch)
        assert "alice@x" in c._fingerprint_changed

    def test_a_changed_fingerprint_does_not_move_on_to_smp(self, statedir, monkeypatch):
        db = self._db(statedir)
        db.add_trust("alice@x", "AAAA")
        c = _FakeClient(db)
        _run_tofu(c, "alice@x", "BBBB", monkeypatch)
        assert c.prompted == [], (
            "the session continued into SMP setup with an unresolved identity "
            "change")

    def test_the_block_refuses_voice(self, statedir, monkeypatch):
        xmpp = pytest.importorskip("otrv4plus_xmpp")
        db = self._db(statedir)
        db.add_trust("alice@x", "AAAA")
        c = _FakeClient(db)
        _run_tofu(c, "alice@x", "BBBB", monkeypatch)
        assert xmpp.OTRv4PlusXMPP._voice_blocked_by_tofu(c, "alice@x") is True
        assert xmpp.OTRv4PlusXMPP._voice_blocked_by_tofu(c, "bob@x") is False

    def test_clearing_the_pin_releases_the_block(self, statedir, monkeypatch):
        xmpp = pytest.importorskip("otrv4plus_xmpp")
        db = self._db(statedir)
        db.add_trust("alice@x", "AAAA")
        c = _FakeClient(db)
        _run_tofu(c, "alice@x", "BBBB", monkeypatch)
        monkeypatch.setattr("builtins.print", lambda *a, **k: None)
        xmpp.OTRv4PlusXMPP.trust_reset(c, "alice@x")
        assert xmpp.OTRv4PlusXMPP._voice_blocked_by_tofu(c, "alice@x") is False
        assert self._db(statedir).check_or_pin("alice@x", "BBBB") is False


class TestTofuDoesNotAuthoriseVoice:

    def test_voice_still_gates_on_smp_only(self):
        # TOFU is identity continuity. SMP is authentication. If a pin ever
        # becomes sufficient for a call, that is a downgrade.
        import inspect
        voice = pytest.importorskip("otrv4plus_voice")
        src = inspect.getsource(voice.VoiceCallManager._smp_verified)
        for banned in ("trust_db", "is_peer_trusted", "check_or_pin",
                       "fingerprint"):
            assert banned not in src, (
                "_smp_verified consults %s; voice must gate on SMP alone"
                % banned)

    def test_the_mismatch_block_only_ever_refuses(self):
        """Parse the guard, do not grep it -- its docstring names the very
        identifiers a textual check would look for.

        The guard is additive: it may return True (refuse) or False (defer to
        the existing SMP gate). It must not itself start a call, and it must
        not consult SMP state, because then it would be a second, weaker
        authorisation path rather than an extra refusal.
        """
        import ast, inspect
        xmpp = pytest.importorskip("otrv4plus_xmpp")
        fn = ast.parse(textwrap_dedent(
            inspect.getsource(xmpp.OTRv4PlusXMPP._voice_blocked_by_tofu))).body[0]
        # Drop the docstring so only executable code is examined.
        body = fn.body
        if (body and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
                and isinstance(body[0].value.value, str)):
            body = body[1:]
        names = set()
        for node in body:
            for sub in ast.walk(node):
                if isinstance(sub, ast.Name):
                    names.add(sub.id)
                elif isinstance(sub, ast.Attribute):
                    names.add(sub.attr)
        assert "_fingerprint_changed" in names, "the guard reads no mismatch state"
        for banned in ("start_call", "answer_call", "_smp_verified",
                       "is_smp_verified"):
            assert banned not in names, (
                "the voice-mismatch guard touches %s; it must only refuse"
                % banned)

        returns = [n for n in ast.walk(fn) if isinstance(n, ast.Return)]
        assert returns, "the guard never returns"
        for r in returns:
            assert isinstance(r.value, ast.Constant) and isinstance(r.value.value, bool), (
                "the guard returns something other than a literal bool")
