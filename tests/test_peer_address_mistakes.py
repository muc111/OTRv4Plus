"""A wrong `--peer` must look like a wrong `--peer`.

A device run was started with `--peer bob@xmpp-elite`, missing the `.i2p`.
Nothing about that address is malformed — one `@`, a non-empty local part, a
non-empty domain — so `_check_jid` passed it. What followed looked like a
protocol bug for the whole session, and both people concluded the software was
broken at one end:

  * the outgoing DAKE was bounced by the server ("Communication with remote
    domains is not enabled"), printed once and never explained;
  * the *peer's* DAKE arrived and established a session under their real JID,
    so the log showed ENCRYPTED, fingerprints, and SMP all working;
  * `/smp` then said "no encrypted session with bob@xmpp-elite. Run /otr
    first" — about an address that could never have one — while a fully
    verified session sat under `bob@xmpp-elite.i2p`;
  * the verified banner printed twice, once per identity.

None of these were wrong individually. Together they told the user everything
except the one thing that mattered.
"""

import io
import os
import re
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

xmpp = pytest.importorskip("otrv4plus_xmpp")


def _client(encrypted=()):
    client = xmpp.OTRv4PlusXMPP.__new__(xmpp.OTRv4PlusXMPP)
    client._encrypted = set(encrypted)
    client.boundjid = None
    return client


class TestTheStartupWarning:
    """Caught before a single stanza goes out, which is the cheapest place."""

    def _warn(self, jid, peer, capsys):
        src = io.open(os.path.join(ROOT, "otrv4plus_xmpp.py"),
                      encoding="utf-8").read()
        # The checker lives inside main(); lift it out rather than run main().
        start = src.index("    def _warn_if_domains_differ(jid, peer):")
        end = src.index("    def _check_jid(value, label):")
        body = src[start:end].replace("\n    ", "\n").lstrip()
        namespace = {}
        exec(body, namespace)
        namespace["_warn_if_domains_differ"](jid, peer)
        return capsys.readouterr().out

    def test_matching_domains_say_nothing(self, capsys):
        out = self._warn("alice@xmpp-elite.i2p", "bob@xmpp-elite.i2p", capsys)
        assert out.strip() == "", "it warns about a perfectly ordinary pair"

    def test_a_truncated_peer_is_reported(self, capsys):
        out = self._warn("alice@xmpp-elite.i2p", "bob@xmpp-elite", capsys)
        assert "DIFFERENT servers" in out

    def test_it_names_the_missing_part_and_the_fix(self, capsys):
        """The whole value is turning "something is wrong" into "type this"."""
        out = self._warn("alice@xmpp-elite.i2p", "bob@xmpp-elite", capsys)
        assert "'.i2p'" in out or '".i2p"' in out
        assert "--peer bob@xmpp-elite.i2p" in out

    def test_it_does_not_refuse_a_genuinely_federated_pair(self, capsys):
        """Cross-domain XMPP is ordinary and this client must not block it."""
        out = self._warn("alice@one.i2p", "bob@two.i2p", capsys)
        assert "DIFFERENT servers" in out
        assert "Continuing" in out
        # No fix suggested, because there is nothing to suggest.
        assert "Did you mean" not in out

    def test_a_missing_argument_is_not_an_error(self, capsys):
        assert self._warn("alice@x.i2p", None, capsys).strip() == ""
        assert self._warn(None, "bob@x.i2p", capsys).strip() == ""


class TestTheNoSessionHintNamesTheRealPeer:
    """"Run /otr first" is sound advice unless /otr can never work."""

    def test_it_is_silent_when_there_is_genuinely_no_session(self):
        assert _client()._no_session_hint("bob@xmpp-elite.i2p") == ""

    def test_it_names_a_session_held_under_another_address(self):
        hint = _client({"bob@xmpp-elite.i2p"})._no_session_hint(
            "bob@xmpp-elite")
        assert "bob@xmpp-elite.i2p" in hint
        assert "encrypted session" in hint

    def test_it_spots_the_truncation_specifically(self):
        hint = _client({"bob@xmpp-elite.i2p"})._no_session_hint(
            "bob@xmpp-elite")
        assert "truncated" in hint

    def test_it_says_commands_follow_peer(self):
        """Without this the user knows the session exists and still has no
        idea why the command cannot see it."""
        hint = _client({"bob@xmpp-elite.i2p"})._no_session_hint(
            "bob@xmpp-elite")
        assert "--peer" in hint

    def test_it_does_not_claim_a_truncation_that_is_not_there(self):
        hint = _client({"carol@elsewhere.i2p"})._no_session_hint(
            "bob@xmpp-elite.i2p")
        assert "carol@elsewhere.i2p" in hint
        assert "truncated" not in hint

    def test_a_session_with_the_asked_for_peer_is_not_offered_back(self):
        """It would read as "there is no session with X, but there is one
        with X", which is worse than silence."""
        assert _client({"bob@x.i2p"})._no_session_hint("bob@x.i2p") == ""

    def test_every_no_session_message_carries_it(self):
        """Four call sites. One left without the hint is the one the user
        hits."""
        src = io.open(os.path.join(ROOT, "otrv4plus_xmpp.py"),
                      encoding="utf-8").read()
        bare = len(re.findall(
            r'no encrypted session with \{peer\}\. Run /otr first\."\)', src))
        assert bare == 0, (
            "%d 'no encrypted session' message(s) still give advice that "
            "cannot work" % bare)
        assert src.count("_no_session_hint(peer)") == 4


class TestTheServerRejectionIsExplained:

    def test_the_handler_recognises_a_refused_domain(self):
        import inspect
        src = inspect.getsource(xmpp.OTRv4PlusXMPP._on_message_error)
        assert "remote domains" in src and "remote-server" in src

    def test_it_says_nothing_will_arrive(self):
        """It was printed once, unexplained, and the run carried on for
        minutes while every message was dropped at the server."""
        import inspect
        src = inspect.getsource(xmpp.OTRv4PlusXMPP._on_message_error)
        assert "will arrive" in src

    def test_the_subscription_case_is_untouched(self):
        import inspect
        src = inspect.getsource(xmpp.OTRv4PlusXMPP._on_message_error)
        assert "not mutually subscribed" in src
