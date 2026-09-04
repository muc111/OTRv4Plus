#!/usr/bin/env python3
"""TLS verification is decided by the transport, not by a flag.

WHY
===
Over I2P and over Tor to an .onion, the ADDRESS is a public key.  A `.b32.i2p`
label is the SHA-256 of the destination's key; a v3 onion name is the key
itself.  Reaching that address means reaching that key-holder, over the
transport's own end-to-end encryption, or not connecting at all.  There is no
certificate authority in the path and no MITM position for one to defend
against.

Users therefore had to pass `--insecure-tls` on every connection to get past a
check that was not protecting anything.  A flag with "insecure" in its name,
typed daily for a link that is not insecure, is worse than useless: it teaches
a habit that is genuinely dangerous the first time it is carried to a clearnet
server, where nothing replaces a CA-valid certificate.

WHAT MUST STAY TRUE
===================
The relaxation is tied to the transport.  Clearnet must still verify, and the
only way to turn that off must still be an explicit flag that warns.  These
tests read `main` rather than driving a live connection, because the property
is which branch sets the SSL context.
"""

import ast
import inspect
import os
import sys
import textwrap

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

xmpp = pytest.importorskip("otrv4plus_xmpp")


def _main_src():
    return textwrap.dedent(inspect.getsource(xmpp.main))


def _main_tree():
    return ast.parse(_main_src())


class TestTheDecisionIsTheTransports:

    def test_the_relaxation_is_not_the_flag_alone(self):
        """`relax_tls = args.insecure_tls` on its own would mean the flag is
        still required over I2P."""
        src = _main_src()
        assert "endpoint_authenticated_by" in src, (
            "nothing records why the endpoint is trusted")
        i = src.index("relax_tls")
        line = src[i:src.index("\n", i)]
        assert "endpoint_authenticated_by" in line, (
            "the relaxation ignores the transport: %r" % line)

    def test_i2p_authenticates_the_endpoint(self):
        src = _main_src()
        i = src.index("endpoint_authenticated_by = None")
        window = src[i:i + 400]
        assert "use_i2p" in window and '"I2P"' in window

    def test_onion_over_tor_authenticates_the_endpoint(self):
        src = _main_src()
        i = src.index("endpoint_authenticated_by = None")
        window = src[i:i + 400]
        assert ".onion" in window and '"Tor"' in window

    def test_tor_to_a_non_onion_is_not_treated_as_authenticated(self):
        """Tor to a clearnet host gives no endpoint key -- the exit sees an
        ordinary TLS session, so the certificate is all there is."""
        src = _main_src()
        i = src.index("endpoint_authenticated_by = None")
        window = src[i:i + 400]
        assert 'server_b32.endswith(".onion")' in window, (
            "any Tor connection is being treated as self-authenticating")


class TestClearnetStillVerifies:

    def test_clearnet_without_the_flag_sets_no_permissive_context(self):
        """The SSL context must be built only under relax_tls."""
        tree = _main_tree()
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign):
                continue
            targets = [t for t in node.targets
                       if isinstance(t, ast.Attribute)
                       and t.attr == "ssl_context"]
            if not targets:
                continue
            # walk up: the assignment must sit inside `if relax_tls:`
            enclosing = [n for n in ast.walk(tree)
                         if isinstance(n, ast.If)
                         and any(node is sub for sub in ast.walk(n))]
            guards = []
            for n in enclosing:
                guards.extend(x.id for x in ast.walk(n.test)
                              if isinstance(x, ast.Name))
            assert "relax_tls" in guards, (
                "client.ssl_context is set outside the relax_tls guard, so "
                "clearnet verification could be disabled unconditionally")

    def test_cert_none_appears_exactly_once(self):
        src = _main_src()
        assert src.count("CERT_NONE") == 1, (
            "more than one path disables verification; there should be one")

    def test_the_clearnet_warning_survives(self):
        src = _main_src()
        assert "CLEARNET connection disables" in src
        assert "capture your XMPP password" in src

    def test_clearnet_says_verification_is_on(self):
        assert "certificate verification ON (clearnet)" in _main_src()


class TestTheFlagIsNoLongerNeeded:

    def test_no_documented_i2p_command_passes_it(self):
        """A flag nobody has to type is the point of the change."""
        readme = open(os.path.join(ROOT, "README.md"), encoding="utf-8").read()
        for block in readme.split("```"):
            if "otrv4plus_xmpp.py" not in block:
                continue
            if ".i2p" in block:
                assert "--insecure-tls" not in block, (
                    "a documented I2P command still passes --insecure-tls:\n%s"
                    % block.strip()[:300])

    def test_the_module_docstring_example_does_not_pass_it(self):
        doc = xmpp.__doc__ or ""
        i = doc.find("otrv4plus_xmpp.py")
        if i != -1:
            assert "--insecure-tls" not in doc[i:i + 400]

    def test_the_help_says_it_is_not_needed_for_i2p_or_onion(self):
        src = inspect.getsource(xmpp.main)
        i = src.index('"--insecure-tls"')
        window = src[i:i + 500]
        assert "Not needed" in window
        assert ".i2p" in window and ".onion" in window

    def test_passing_it_redundantly_is_reported(self):
        src = _main_src()
        assert "was passed and is not needed here" in src


class TestTheExplanationIsAccurate:
    """The message replaces a scary one; it must not overclaim in the other
    direction."""

    def test_it_says_why_rather_than_just_that(self):
        src = _main_src()
        i = src.index("authenticated by I2P")
        window = src[i:i + 500]
        assert "hash of" in window, (
            "the message asserts the endpoint is authenticated without "
            "saying what authenticates it")

    def test_it_does_not_call_the_connection_verified(self):
        """TLS is not verifying anything here; claiming otherwise would be a
        different lie from the one being removed."""
        src = _main_src()
        i = src.index("authenticated by I2P")
        window = src[i:i + 500].lower()
        assert "certificate verification on" not in window
        assert "verified" not in window
