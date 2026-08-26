#!/usr/bin/env python3
"""`/identity` -- the state TOFU depends on, in one screen.

Written because "it still asks me to trust the fingerprint" has three causes
that look identical from the prompt: an older build at one end, an answer that
was not `y`, or a peer whose identity genuinely changed. Telling them apart
previously meant locating and reading a JSON file on both handsets, which is
enough friction that it did not happen.
"""

import os
import sys
import tempfile

import pytest

from pathlib import Path as _P

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

otr = pytest.importorskip("otrv4_")
xmpp = pytest.importorskip("otrv4plus_xmpp")


@pytest.fixture
def client():
    # tempfile, not pytest's tmp_path: something in this repo's test setup
    # stubs `pwd`, and tmp_path calls getuser() which needs it.
    with tempfile.TemporaryDirectory() as d:
        yield _make_client(d)


def _make_client(d):
    tmp_path = _P(d)
    db = otr.TrustDatabase(str(tmp_path / "trust.json"), persistent=True)

    class FakeOtr:
        def __init__(self):
            self.trust_db = db
            self.config = otr.OTRConfig(
                trust_db_path=str(tmp_path / "trust.json"),
                identity_path=str(tmp_path / "identity.sealed"))
        def get_session(self, peer): return None

    c = xmpp.OTRv4PlusXMPP.__new__(xmpp.OTRv4PlusXMPP)
    c.otr = FakeOtr()
    c._encrypted = set()
    c._fingerprint_changed = {}
    c.identity_persistent = True
    # slixmpp's XMLStream.__del__ touches these. The object here is built with
    # __new__ so no slixmpp constructor ran, and without them every collection
    # raises inside __del__ and pytest reports an unraisable exception.
    c._run_out_filters = False
    c._run_filters = None
    return c


def report(c, capsys):
    """Capture with capsys rather than replacing builtins.print.

    Patching print globally breaks pytest's own machinery -- it errored every
    test after the first -- and a report is exactly the thing worth reading
    through the same path a user sees.
    """
    xmpp.OTRv4PlusXMPP.show_identity(c)
    return capsys.readouterr().out


class TestItAnswersTheQuestionThatWasAsked:

    def test_it_says_whether_the_local_identity_persists(self, client, capsys):
        out = report(client, capsys)
        assert "PERSISTENT" in out

    def test_an_ephemeral_identity_is_called_out_as_wrong_for_xmpp(self, client, capsys):
        client.identity_persistent = False
        out = report(client, capsys)
        assert "EPHEMERAL" in out
        assert "older than v10.12.0" in out, (
            "an ephemeral XMPP identity is the single most likely cause of a "
            "repeating prompt and must name it")

    def test_an_empty_store_explains_what_a_second_prompt_means(self, client, capsys):
        out = report(client, capsys)
        assert "No fingerprints pinned" in out
        assert "SECOND time" in out

    def test_it_lists_pinned_peers(self, client, capsys):
        client.otr.trust_db.add_trust("alice@x", "AAAA")
        client.otr.trust_db.add_trust("bob@x", "BBBB")
        out = report(client, capsys)
        assert "alice@x" in out and "bob@x" in out
        assert "Pinned fingerprints (2)" in out

    def test_it_shows_the_trust_store_path(self, client, capsys):
        assert client.otr.trust_db.db_path in report(client, capsys)

    def test_it_flags_an_in_memory_store(self, client, capsys):
        client.otr.trust_db.persistent = False
        assert "IN MEMORY ONLY" in report(client, capsys), (
            "a store that never reaches disk explains a repeating prompt and "
            "must be visible")

    def test_an_untrusted_pin_is_not_listed_as_pinned(self, client, capsys):
        # check_or_pin records the fingerprint with trusted=False when the user
        # declines. That is exactly the "I answered something other than y"
        # case, and it must not read as pinned.
        client.otr.trust_db.check_or_pin("carol@x", "CCCC")
        out = report(client, capsys)
        assert "No fingerprints pinned" in out
        assert "carol@x" not in out

    def test_it_compares_a_live_session_against_the_pin(self, client, capsys):
        client.otr.trust_db.add_trust("alice@x", "AAAA")
        client._encrypted.add("alice@x")
        client._remote_fp = lambda p: "AAAA"
        assert "matches now" in report(client, capsys)

    def test_a_live_mismatch_is_shouted_about(self, client, capsys):
        client.otr.trust_db.add_trust("alice@x", "AAAA")
        client._encrypted.add("alice@x")
        client._remote_fp = lambda p: "ZZZZ"
        assert "DIFFERS FROM LIVE" in report(client, capsys)

    def test_unresolved_changes_are_reported_with_the_way_out(self, client, capsys):
        client._fingerprint_changed["alice@x"] = "AAAA"
        out = report(client, capsys)
        assert "UNRESOLVED" in out
        assert "/trust-reset" in out

    def test_it_never_raises_on_a_broken_store(self, client, capsys):
        class Broken:
            db_path = "?"
            persistent = True
            def list_trusted(self): raise RuntimeError("boom")
        client.otr.trust_db = Broken()
        out = report(client, capsys)          # must not raise
        assert "unreadable" in out


class TestItIsReachable:

    def test_the_command_is_dispatched(self):
        import inspect
        src = inspect.getsource(xmpp.OTRv4PlusXMPP.dispatch_line)
        assert '"/identity"' in src and "show_identity" in src

    def test_it_is_in_the_help(self):
        import inspect
        src = inspect.getsource(xmpp.OTRv4PlusXMPP)
        assert "/identity            your identity" in src
