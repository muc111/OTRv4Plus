#!/usr/bin/env python3
"""INV-09, INV-10: IRC and XMPP identity state cannot reach each other.

The split is deliberate and is not a feature gap:

  XMPP  a JID is a durable name, so the identity behind it persists and peer
        fingerprints are pinned.  A changed fingerprint means something.

  IRC   a nick is ephemeral, so an identity pinned to one is pinned to
        nothing.  A fresh Ed448 identity every process, and no trust record
        that outlives it.

Both protocols share one engine (`otrv4plus.py` and `otrv4_.py` are symlinks
to `otrv4+.py`), so the separation is entirely in configuration -- which is
exactly the kind of thing that gets "unified" by a well-meaning refactor.
These tests make that unification fail loudly.
"""

import os
import sys
import tempfile

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

otr = pytest.importorskip("otrv4_")


class TestTheDefaultsAreTheIrcContract:
    """IRC constructs OTRConfig with no persistence arguments at all, so the
    defaults ARE the IRC policy.  A default flipping to True would silently
    give every IRC run a persistent identity."""

    def test_identity_persistence_is_off_by_default(self):
        assert otr.OTRConfig().persist_identity is False

    def test_trust_persistence_is_off_by_default(self):
        assert otr.OTRConfig().persist_trust is False

    def test_no_identity_path_by_default(self):
        cfg = otr.OTRConfig()
        assert cfg.identity_path is None
        assert cfg.identity_dek_path is None

    def test_they_are_separate_switches(self):
        """Identity persistence can be unavailable while trust pinning is
        still wanted, so one must not imply the other."""
        cfg = otr.OTRConfig(persist_trust=True)
        assert cfg.persist_identity is False


class TestAnIrcTrustDatabaseNeverWrites:

    def test_a_non_persistent_database_creates_no_file(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "trust.json")
            db = otr.TrustDatabase(path, persistent=False)
            db.add_trust("someone", "AA" * 64)
            assert not os.path.exists(path), (
                "an IRC run wrote a trust file")

    def test_it_still_works_in_memory(self):
        with tempfile.TemporaryDirectory() as d:
            db = otr.TrustDatabase(os.path.join(d, "trust.json"),
                                   persistent=False)
            db.add_trust("someone", "AA" * 64)
            assert db.is_trusted("someone", "AA" * 64)

    def test_a_persistent_database_does_write(self):
        """The other half: XMPP must actually persist."""
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "trust.json")
            db = otr.TrustDatabase(path, persistent=True)
            db.add_trust("someone@example.i2p", "BB" * 64)
            assert os.path.exists(path)

    def test_a_persistent_pin_survives_a_reload(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "trust.json")
            otr.TrustDatabase(path, persistent=True).add_trust(
                "someone@example.i2p", "BB" * 64)
            assert otr.TrustDatabase(path, persistent=True).is_trusted(
                "someone@example.i2p", "BB" * 64)

    def test_the_save_path_is_guarded_not_the_call_sites(self):
        """Guarding every caller is a rule someone will forget; guarding the
        writer is a rule the code enforces."""
        import inspect
        src = inspect.getsource(otr.TrustDatabase._save)
        head = src[:src.index("with self._lock")]
        assert "if not self.persistent" in head
        assert "return" in head


class TestTheStoresAreInDifferentPlaces:

    def test_xmpp_uses_its_own_directory(self):
        xmpp = pytest.importorskip("otrv4plus_xmpp")
        assert xmpp.XMPP_STATE_DIR.rstrip("/").endswith("/xmpp")

    def test_every_xmpp_path_is_under_that_directory(self):
        xmpp = pytest.importorskip("otrv4plus_xmpp")
        cfg = xmpp._xmpp_otr_config()
        for name in ("trust_db_path", "smp_secrets_path", "identity_path",
                     "identity_dek_path"):
            value = getattr(cfg, name)
            assert value, "%s is unset for XMPP" % name
            assert value.startswith(xmpp.XMPP_STATE_DIR), (
                "%s escapes the XMPP state directory: %s" % (name, value))

    def test_the_xmpp_config_turns_both_switches_on(self):
        xmpp = pytest.importorskip("otrv4plus_xmpp")
        cfg = xmpp._xmpp_otr_config()
        assert cfg.persist_identity is True
        assert cfg.persist_trust is True

    def test_only_one_function_diverges_from_the_defaults(self):
        """If a second place starts setting persist_identity, the policy has
        two sources of truth and they will drift."""
        import ast
        import inspect
        xmpp = pytest.importorskip("otrv4plus_xmpp")
        tree = ast.parse(inspect.getsource(xmpp))
        setters = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef):
                continue
            for sub in ast.walk(node):
                if (isinstance(sub, ast.keyword)
                        and sub.arg in ("persist_identity", "persist_trust")):
                    setters.append(node.name)
        assert set(setters) == {"_xmpp_otr_config"}, (
            "persistence is configured in %s; it should be one place"
            % sorted(set(setters)))


class TestIrcDoesNotImportTheIdentityModule:
    """Keeping the wiring in its own module means the IRC client never
    imports any of it, so the separation is visible rather than a flag deep
    in a constructor."""

    def test_the_engine_never_imports_it_at_module_scope(self):
        """A module-scope import would load the persistence machinery into
        every IRC run.  The engine imports it inside the opted-in branch
        instead, which makes the separation checkable rather than a promise."""
        import ast
        tree = ast.parse(open(os.path.join(ROOT, "otrv4+.py"),
                              encoding="utf-8").read())
        for node in tree.body:                      # top level only
            if isinstance(node, ast.ImportFrom) and node.module:
                assert "otrv4plus_identity" not in node.module, (
                    "the shared engine imports the XMPP identity module at "
                    "module scope (line %d); IRC would then load it too"
                    % node.lineno)
            if isinstance(node, ast.Import):
                for a in node.names:
                    assert "otrv4plus_identity" not in a.name, node.lineno

    def test_every_identity_import_is_guarded_by_persist_identity(self):
        import ast
        tree = ast.parse(open(os.path.join(ROOT, "otrv4+.py"),
                              encoding="utf-8").read())
        found = 0
        for fn in ast.walk(tree):
            if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            imports = [n for n in ast.walk(fn)
                       if isinstance(n, ast.ImportFrom)
                       and (n.module or "") == "otrv4plus_identity"]
            if not imports:
                continue
            found += len(imports)
            body = ast.get_source_segment(
                open(os.path.join(ROOT, "otrv4+.py"), encoding="utf-8").read(),
                fn)
            guard = body.index("persist_identity")
            assert guard < body.index("otrv4plus_identity"), (
                "%s imports the identity module before checking "
                "persist_identity" % fn.name)
        assert found >= 1, "nothing loads the identity module any more"

    def test_the_identity_module_says_why_it_is_separate(self):
        src = open(os.path.join(ROOT, "otrv4plus_identity.py"),
                   encoding="utf-8").read()
        head = src[:src.index('"""', 3)]
        assert "IRC" in head and "XMPP" in head
        assert "filesystem permissions" in head.lower(), (
            "the module must keep stating what actually protects the "
            "identity at rest, because it is not cryptography")

    def test_persistent_identity_fails_closed(self):
        """A silent fallback to an ephemeral identity would change the local
        fingerprint without telling anyone, and every peer would read that as
        the identity change TOFU exists to flag."""
        ident = pytest.importorskip("otrv4plus_identity")
        assert issubclass(ident.IdentityUnavailable, RuntimeError)
        src = open(os.path.join(ROOT, "otrv4plus_identity.py"),
                   encoding="utf-8").read()
        assert "Raised rather than falling back" in src
