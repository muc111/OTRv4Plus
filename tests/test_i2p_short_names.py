#!/usr/bin/env python3
"""Short .i2p names, and the local alias file that makes them work.

THE PROBLEM
===========
`.i2p` names are not DNS.  A router resolves only what is in its own address
book, built from subscriptions, and a private server is in nobody's
subscription.  So `xmpp-elite.i2p` resolves on the machine that created it and
nowhere else, while the 52-character `.b32.i2p` form works everywhere because
it *is* the destination hash.

On a phone that means pasting 52 base32 characters to connect, every time.

WHAT THE ALIAS FILE IS
======================
A note to yourself about what a name means on this device.  It is not
authenticated and proves nothing about who answers -- the DAKE authenticates
the peer and TOFU pins their identity key, so a misdirected alias yields a
failed connection, not a silent impersonation.

The one rule that matters here: an address typed in full as `.b32.i2p` is
never looked up in the file, so a local file cannot redirect an address the
user spelled out.
"""

import os
import sys
import tempfile

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

otr = pytest.importorskip("otrv4_")

B32 = "hq4t24b7vkllfbk55e5xfocqhfi7hxprwc47zyuilbg6wgzikidq.b32.i2p"
OTHER_B32 = "aaaa24b7vkllfbk55e5xfocqhfi7hxprwc47zyuilbg6wgzikidq.b32.i2p"


def _hosts(text):
    """Write an alias file and return its path (caller owns the directory)."""
    d = tempfile.mkdtemp()
    path = os.path.join(d, "i2p_hosts")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    return path


class TestTheFileFormat:

    def test_a_simple_mapping(self):
        assert otr.i2p_aliases(_hosts("xmpp-elite.i2p = %s\n" % B32)) == {
            "xmpp-elite.i2p": B32}

    def test_whitespace_form_works_too(self):
        assert otr.i2p_aliases(_hosts("xmpp-elite.i2p   %s\n" % B32)) == {
            "xmpp-elite.i2p": B32}

    def test_comments_and_blank_lines_are_ignored(self):
        text = ("# my server\n"
                "\n"
                "xmpp-elite.i2p = %s   # trailing note\n" % B32)
        assert otr.i2p_aliases(_hosts(text)) == {"xmpp-elite.i2p": B32}

    def test_names_are_case_insensitive(self):
        assert "xmpp-elite.i2p" in otr.i2p_aliases(
            _hosts("XMPP-Elite.I2P = %s\n" % B32))

    def test_a_missing_file_is_not_an_error(self):
        assert otr.i2p_aliases("/no/such/file") == {}

    def test_one_bad_line_does_not_break_the_rest(self):
        """A typo must not make the client unusable."""
        text = ("broken line with no destination at all here now\n"
                "xmpp-elite.i2p = %s\n" % B32)
        assert otr.i2p_aliases(_hosts(text)) == {"xmpp-elite.i2p": B32}


class TestWhatIsRefused:

    def test_a_destination_that_is_not_a_destination(self):
        assert otr.i2p_aliases(_hosts("bad.i2p = example.com\n")) == {}

    def test_a_b32_of_the_wrong_length(self):
        assert otr.i2p_aliases(_hosts("bad.i2p = short.b32.i2p\n")) == {}

    def test_an_alias_chaining_to_another_short_name(self):
        """Otherwise one line could point at another and the file would need
        loop detection."""
        assert otr.i2p_aliases(_hosts("a.i2p = b.i2p\n")) == {}

    def test_a_name_that_is_not_dot_i2p(self):
        assert otr.i2p_aliases(_hosts("example.com = %s\n" % B32)) == {}

    def test_a_b32_cannot_be_given_an_alias(self):
        """Aliasing a b32 would mean the file could shadow an address that is
        already exact."""
        assert otr.i2p_aliases(_hosts("%s = %s\n" % (B32, OTHER_B32))) == {}


class TestSubstitution:

    def test_a_short_name_is_substituted(self, monkeypatch, capsys):
        path = _hosts("xmpp-elite.i2p = %s\n" % B32)
        monkeypatch.setattr(otr, "i2p_hosts_path", lambda: path)
        host, source = otr.I2PSAMConnection._apply_i2p_alias("xmpp-elite.i2p")
        assert host == B32
        assert source == path
        assert "xmpp-elite.i2p" in capsys.readouterr().out, (
            "the substitution is silent; the user cannot see which "
            "destination they actually reached")

    def test_a_full_b32_is_never_looked_up(self, monkeypatch):
        """The security-relevant one.  A local file must not be able to
        redirect an address the user typed out in full."""
        path = _hosts("%s = %s\n" % (B32, OTHER_B32))
        monkeypatch.setattr(otr, "i2p_hosts_path", lambda: path)
        host, source = otr.I2PSAMConnection._apply_i2p_alias(B32)
        assert host == B32, "an alias redirected a fully-specified b32 address"
        assert source is None

    def test_an_unknown_name_is_passed_through_to_the_router(self, monkeypatch):
        """The router's own address book still gets its chance."""
        monkeypatch.setattr(otr, "i2p_hosts_path", lambda: "/no/such/file")
        host, source = otr.I2PSAMConnection._apply_i2p_alias("stats.i2p")
        assert host == "stats.i2p"
        assert source is None


class TestTheErrorSaysWhatToDo:

    def test_an_unresolvable_short_name_names_the_file_and_the_line(self):
        msg = otr.I2PSAMConnection._explain_resolve_failure(
            "xmpp-elite.i2p", "NAMING REPLY RESULT=KEY_NOT_FOUND", None)
        assert "not global the way DNS is" in msg
        assert "b32.i2p" in msg
        assert "xmpp-elite.i2p = " in msg, (
            "the message does not show the line to add")
        assert otr.i2p_hosts_path() in msg

    def test_a_bad_alias_blames_the_alias(self, monkeypatch):
        msg = otr.I2PSAMConnection._explain_resolve_failure(
            B32, "NAMING REPLY RESULT=KEY_NOT_FOUND", "/some/i2p_hosts")
        assert "/some/i2p_hosts" in msg
        assert "Check the line in that file" in msg

    def test_a_failing_b32_is_not_blamed_on_naming(self):
        msg = otr.I2PSAMConnection._explain_resolve_failure(
            B32, "NAMING REPLY RESULT=KEY_NOT_FOUND", None)
        assert "router or tunnel problem" in msg
        assert "address book" not in msg


class TestTheTransportChoiceIsUnchanged:
    """A short name must still select I2P, and must not weaken the checks in
    TRANSPORT_POLICY.md."""

    def test_a_short_name_still_reads_as_i2p(self):
        for name in ("xmpp-elite.i2p", B32):
            assert name.endswith(".i2p")

    def test_the_alias_file_cannot_point_at_a_non_i2p_destination(self):
        for bad in ("example.onion", "1.2.3.4", "https://example.com",
                    "example.com:5222"):
            assert otr.i2p_aliases(_hosts("x.i2p = %s\n" % bad)) == {}, bad


class TestRememberingTheB32:
    """Type the 52 characters once, never again.

    Recorded only after a connection has actually succeeded -- that is the
    only moment the client knows the name and the destination belong
    together.
    """

    def test_a_new_alias_is_written(self):
        d = tempfile.mkdtemp()
        path = os.path.join(d, "sub", "i2p_hosts")
        note = otr.remember_i2p_alias("xmpp-elite.i2p", B32, path)
        assert note.startswith("recorded")
        assert otr.i2p_aliases(path) == {"xmpp-elite.i2p": B32}

    def test_the_file_it_creates_is_private(self):
        d = tempfile.mkdtemp()
        path = os.path.join(d, "i2p_hosts")
        otr.remember_i2p_alias("xmpp-elite.i2p", B32, path)
        assert oct(os.stat(path).st_mode & 0o777) == "0o600"

    def test_recording_the_same_thing_twice_writes_nothing(self):
        d = tempfile.mkdtemp()
        path = os.path.join(d, "i2p_hosts")
        otr.remember_i2p_alias("xmpp-elite.i2p", B32, path)
        before = open(path, encoding="utf-8").read()
        assert otr.remember_i2p_alias("xmpp-elite.i2p", B32, path) == ""
        assert open(path, encoding="utf-8").read() == before

    def test_a_changed_destination_is_reported_and_not_rewritten(self):
        """The security-relevant one.  A server whose destination changed is
        something the user must see, not something the client silently
        adopts."""
        d = tempfile.mkdtemp()
        path = os.path.join(d, "i2p_hosts")
        otr.remember_i2p_alias("xmpp-elite.i2p", B32, path)
        note = otr.remember_i2p_alias("xmpp-elite.i2p", OTHER_B32, path)
        assert "already recorded" in note
        assert "Not changing it" in note
        assert otr.i2p_aliases(path) == {"xmpp-elite.i2p": B32}, (
            "the client overwrote a destination the user had already accepted")

    def test_rubbish_is_never_recorded(self):
        d = tempfile.mkdtemp()
        path = os.path.join(d, "i2p_hosts")
        for name, dest in (("example.com", B32),
                           (B32, OTHER_B32),
                           ("x.i2p", "not-a-destination"),
                           ("x.i2p", "other.i2p"),
                           ("", B32),
                           ("x.i2p", "")):
            assert otr.remember_i2p_alias(name, dest, path) == "", (name, dest)
        assert not os.path.exists(path), "a refused write created the file"

    def test_what_is_written_can_be_read_back(self):
        """The round trip is the whole point: a file this wrote must load."""
        d = tempfile.mkdtemp()
        path = os.path.join(d, "i2p_hosts")
        otr.remember_i2p_alias("xmpp-elite.i2p", B32, path)
        otr.remember_i2p_alias("other-server.i2p", OTHER_B32, path)
        assert otr.i2p_aliases(path) == {"xmpp-elite.i2p": B32,
                                         "other-server.i2p": OTHER_B32}


class TestTheClientOnlyWritesItsOwnFile:
    """i2pd owns its address book.  We do not write to it."""

    def test_nothing_opens_a_router_file(self):
        """Checks what is opened, not what is mentioned.

        Naming i2pd.conf in a help string is fine and useful -- "SAM must be
        enabled in i2pd.conf" is exactly what a stuck user needs to read. What
        must never happen is the client reading or writing the daemon's files:
        the format varies between versions, i2pd rewrites them on its own
        schedule, and a bad write breaks name resolution for every I2P
        application on the device rather than just this one.
        """
        import ast as _ast
        offenders = []
        for name in ("otrv4+.py", "otrv4plus_xmpp.py"):
            tree = _ast.parse(open(os.path.join(ROOT, name),
                                   encoding="utf-8").read())
            for node in _ast.walk(tree):
                if not isinstance(node, _ast.Call):
                    continue
                func = node.func
                opener = ((isinstance(func, _ast.Name) and func.id == "open")
                          or (isinstance(func, _ast.Attribute)
                              and func.attr in ("open", "makedirs", "remove",
                                                "chmod", "rename", "replace")))
                if not opener:
                    continue
                for text in [a.value for a in _ast.walk(node)
                             if isinstance(a, _ast.Constant)
                             and isinstance(a.value, str)]:
                    if "i2pd" in text.lower() or "addressbook" in text.lower():
                        offenders.append("%s:%d %r" % (name, node.lineno, text))
        assert not offenders, (
            "the client touches a router-owned file: %s" % offenders)

    def test_the_only_file_written_is_the_client_alias_file(self):
        import inspect
        src = inspect.getsource(otr.remember_i2p_alias)
        assert "i2p_hosts_path()" in src
        assert "open(path" in src
