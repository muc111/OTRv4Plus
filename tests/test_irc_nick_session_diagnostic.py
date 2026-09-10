"""A nick is not an identity, and the client has to say so out loud.

Sessions now survive a transport reconnect (v10.24.0). That makes a specific
confusion likelier, not rarer: a peer comes back under a different IRC nick,
the preserved session is keyed by the old one, and nothing matches.

Two ways that showed up, and both were silent:

  * The peer changed nick on a live connection. The server said so, the
    client updated the channel user list and the OTRv4+ marker, and said
    nothing about the encrypted session it holds under the old name.
  * An encrypted message arrived from a nick with no session.
    `_handle_data_message` opened with a bare `return`. The message was
    dropped and nothing was printed, which looks exactly like the peer having
    said nothing.

WHAT THE FIX MUST NOT DO
========================
Move the session. Following a rename would mean encrypting to whoever holds a
name now, and the server hands names out and takes them back. Keys follow the
handshake that produced them. The preserved session stays with the old nick
and a new DAKE is required -- deliberately, and the tests below pin it.

Nor may the message claim more than is known. On the live-NICK path the
server told us authoritatively that one connection changed name, so that
message can name both. On the undecryptable-message path there is no evidence
at all about who sent it -- the message did not decrypt -- so the text reports
what is true (no session for this nick, sessions held for these others) and
leaves the identification to the user and the fingerprint.

Enforces INV-11: an OTR session is never re-keyed onto a new IRC nick, so a
name the server just reassigned can never inherit keys pinned to someone else.
"""

import re

import pytest

otr = pytest.importorskip("otrv4plus")

CLIENT = otr.EnhancedOTRv4IRCClient
OLD = "IronFenrir"
NEW = "SwiftOmega"

_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def plain(text):
    return _ANSI.sub("", str(text))


class Manager:
    def __init__(self, peers=()):
        self.sessions = {p: object() for p in peers}

    def has_session(self, peer):
        return peer in self.sessions

    def get_security_level(self, peer):
        return (otr.UIConstants.SecurityLevel.SMP_VERIFIED
                if peer in self.sessions
                else otr.UIConstants.SecurityLevel.PLAINTEXT)


class Client:
    METHODS = ("_warn_nick_change_keeps_session", "_warn_no_session_for_nick",
               "_other_session_nicks", "_clear_no_session_warning")

    #: The stub stands in for the class, so it carries the class attributes
    #: the borrowed methods read. Referenced rather than copied: a change to
    #: the bound in production must not leave this testing a stale number.
    _NO_SESSION_WARNED_MAX = CLIENT._NO_SESSION_WARNED_MAX

    def __init__(self, peers=(OLD,)):
        self.lines = []
        self.targets = []
        self.session_manager = Manager(peers)
        for name in self.METHODS:
            setattr(self, name, getattr(CLIENT, name).__get__(self))

    def add_message(self, target, message, sec=None):
        self.targets.append(target)
        self.lines.append(plain(message))

    def debug(self, *a, **k):
        pass

    @property
    def text(self):
        return "\n".join(self.lines)


@pytest.fixture
def client():
    return Client()


class TestALiveNickChange:
    """The server told us; the message may name both nicks."""

    def test_it_says_the_session_did_not_move(self, client):
        client._warn_nick_change_keeps_session(OLD, NEW)
        assert "NOT CARRIED OVER" in client.text

    def test_it_names_both_nicks(self, client):
        client._warn_nick_change_keeps_session(OLD, NEW)
        assert OLD in client.text and NEW in client.text

    def test_it_says_a_new_session_is_needed(self, client):
        client._warn_nick_change_keeps_session(OLD, NEW)
        assert "/otr %s" % NEW in client.text

    def test_it_tells_the_user_to_compare_the_fingerprint(self, client):
        """The new nick is first contact under TOFU, so the pin they already
        have is the only thing that connects the two."""
        client._warn_nick_change_keeps_session(OLD, NEW)
        assert "fingerprint" in client.text

    def test_it_offers_a_way_to_clear_the_old_session(self, client):
        client._warn_nick_change_keeps_session(OLD, NEW)
        assert "/endotr %s" % OLD in client.text

    def test_it_lands_in_the_tab_where_the_conversation_was(self, client):
        client._warn_nick_change_keeps_session(OLD, NEW)
        assert set(client.targets) == {OLD}

    def test_a_hostile_nick_cannot_inject_escapes(self, client):
        client._warn_nick_change_keeps_session(OLD, "evil\x1b[2Jnick")
        assert "\x1b[2J" not in "".join(client.lines)


class TestAnUndecryptableMessage:
    """No evidence about the sender, so the message claims nothing about them."""

    def test_it_reports_the_missing_session(self, client):
        client._warn_no_session_for_nick(NEW)
        assert "OTR SESSION NOT FOUND" in client.text

    def test_it_says_the_message_was_dropped(self, client):
        client._warn_no_session_for_nick(NEW)
        assert "dropped" in client.text

    def test_it_lists_the_sessions_that_do_exist(self, client):
        client._warn_no_session_for_nick(NEW)
        assert OLD in client.text

    def test_it_does_not_claim_the_sender_is_that_peer(self, client):
        """The message did not decrypt. Asserting who sent it would be a
        guess printed as a fact, next to a fingerprint the user is about to
        rely on."""
        client._warn_no_session_for_nick(NEW)
        assert "If this is one of them" in client.text
        for claimed in ("reconnected as", "is now", "the same person on"):
            assert claimed not in client.text

    def test_with_no_other_sessions_it_lists_none(self):
        c = Client(peers=())
        c._warn_no_session_for_nick(NEW)
        assert "You do have encrypted session" not in c.text
        assert "OTR SESSION NOT FOUND" in c.text

    def test_it_lands_in_the_senders_tab(self, client):
        client._warn_no_session_for_nick(NEW)
        assert set(client.targets) == {NEW}

    def test_a_hostile_nick_cannot_inject_escapes(self, client):
        client._warn_no_session_for_nick("evil\x1b[2Jnick")
        assert "\x1b[2J" not in "".join(client.lines)

    def test_a_hostile_peer_name_in_the_session_list_is_sanitised(self):
        c = Client(peers=("bad\x1b[2Jpeer",))
        c._warn_no_session_for_nick(NEW)
        assert "\x1b[2J" not in "".join(c.lines)


class TestItCannotBeUsedToFloodThePanel:
    """The trigger is a message from an unauthenticated stranger."""

    def test_it_warns_once_per_nick(self, client):
        client._warn_no_session_for_nick(NEW)
        first = len(client.lines)
        for _ in range(50):
            client._warn_no_session_for_nick(NEW)
        assert len(client.lines) == first

    def test_many_nicks_are_bounded(self, client):
        for i in range(500):
            client._warn_no_session_for_nick("nick%d" % i)
        assert len(client._no_session_warned) <= CLIENT._NO_SESSION_WARNED_MAX

    def test_the_bound_does_not_stop_the_first_warnings(self, client):
        client._warn_no_session_for_nick(NEW)
        assert "OTR SESSION NOT FOUND" in client.text


class TestTheWarningResetsWhenASessionExists:

    def test_a_new_session_lets_a_later_drop_be_reported(self, client):
        client._warn_no_session_for_nick(NEW)
        before = len(client.lines)
        client._clear_no_session_warning(NEW)
        client._warn_no_session_for_nick(NEW)
        assert len(client.lines) > before, (
            "the warning is once per process, so a peer who loses a session "
            "later goes silent again -- the behaviour this replaced")

    def test_clearing_an_unknown_nick_is_harmless(self, client):
        client._clear_no_session_warning("nobody")


class TestTheHooksAreWired:
    """The helpers are not the change; the two silent paths calling them is."""

    @staticmethod
    @pytest.fixture(scope="class")
    def tree():
        import ast
        import os
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(root, "otrv4+.py"), encoding="utf-8") as fh:
            return ast.parse(fh.read())

    def test_the_data_path_no_longer_drops_silently(self, tree):
        import ast
        fns = [n for n in ast.walk(tree)
               if isinstance(n, ast.FunctionDef)
               and n.name == "_handle_data_message"]
        srcs = [ast.unparse(n) for n in fns]
        assert any("_warn_no_session_for_nick" in s for s in srcs), (
            "an encrypted message from an unknown nick is dropped in silence "
            "again")

    def test_the_nick_handler_reports_the_stranded_session(self, tree):
        import ast
        fn = next(n for n in ast.walk(tree)
                  if isinstance(n, ast.FunctionDef)
                  and n.name == "handle_message"
                  and "_warn_nick_change_keeps_session" in ast.unparse(n))
        assert fn is not None

    def test_the_session_is_never_re_keyed_to_the_new_nick(self, tree):
        """The security property. Moving a session onto a name the server
        just reassigned is how a preserved session becomes a leak."""
        import ast
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef):
                continue
            src = ast.unparse(node)
            if "_warn_nick_change_keeps_session" not in src:
                continue
            for moved in ("sessions[new_nick]", "sessions.pop(sender)",
                          "sessions[new_nick] = "):
                assert moved not in src, (
                    "the OTR session is being moved onto the new nick")

    def test_establishing_a_session_clears_the_warning(self, tree):
        import ast
        fn = next(n for n in ast.walk(tree)
                  if isinstance(n, ast.FunctionDef)
                  and n.name == "_finish_session_setup")
        assert "_clear_no_session_warning" in ast.unparse(fn)
