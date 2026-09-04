#!/usr/bin/env python3
"""INV-17, INV-18, INV-19: the transport policy, checked rather than promised.

The policy is written out in `TRANSPORT_POLICY.md`.  Three of its rules are
the ones that get broken by well-intentioned changes, so they are pinned here:

  INV-17  no fallback ladder.  A transport that fails or degrades must not
          cause a less private one to be selected.  A network fault becoming
          a deanonymisation is the failure mode; it fires hardest on exactly
          the congested networks where nobody is watching.

  INV-18  the transport class is fixed for the call.  An endpoint may move
          within a class if the move is authenticated -- that is what
          MEDIAPATH is and what recovered the Wi-Fi-to-mobile transition --
          but a class may not change under a running call.

  INV-19  a proxy is routing, not anonymity, and clearnet TLS 1.3 is strong
          encryption with no anonymity rather than weak encryption.  Both
          halves are wording, and wording is what users act on.

Several of these check documents.  That is deliberate: modes 4 and 5 of the
policy (proxy, proxy chain) are not implemented, so the thing that exists to
be broken today is the description, and a wrong description is what the next
implementer will build against.  Where a structural check is possible it is
preferred, and where a capability is added later these tests are the place it
has to prove itself.
"""

import os
import re
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

POLICY = os.path.join(ROOT, "TRANSPORT_POLICY.md")


def _read(path):
    return open(path, encoding="utf-8").read()


def _branch(src, anchor):
    """The body of the `if` starting at `anchor`, and nothing after it.

    A fixed-width window is not good enough here: the two transport refusals
    are adjacent, so a 400-character slice from the first one contains the
    second one's `sys.exit` and the test passes with the first one removed.
    That mutation survived until this helper existed.
    """
    i = src.index(anchor)
    rest = src[i:]
    nxt = rest.find("\n    if ", 1)
    return rest if nxt < 0 else rest[:nxt]


def _repo_documents():
    """Every markdown file at the repository root, excluding the attic."""
    return [os.path.join(ROOT, n) for n in sorted(os.listdir(ROOT))
            if n.endswith(".md")]


# --------------------------------------------------------------------------
# INV-17 -- no fallback ladder
# --------------------------------------------------------------------------

class TestNoFallbackLadder:

    def test_the_policy_names_both_forbidden_sequences(self):
        """The two that sound reasonable, and so keep being proposed."""
        doc = _read(POLICY)
        i = doc.index("must never exist")
        window = doc[i:i + 800]
        assert "try Tor" in window and "try clearnet" in window
        assert "UDP" in window, (
            "the latency-triggered downgrade is the more dangerous of the "
            "two, because it fires on degraded rather than failed")

    def test_contradictory_transport_flags_exit_rather_than_guess(self):
        xmpp = pytest.importorskip("otrv4plus_xmpp")
        src = _read(xmpp.__file__)
        assert "sys.exit" in _branch(src, "if use_i2p and use_tor:"), (
            "--tor with an .i2p server picks a transport instead of refusing")

    def test_an_onion_address_without_tor_refuses(self):
        xmpp = pytest.importorskip("otrv4plus_xmpp")
        src = _read(xmpp.__file__)
        assert "sys.exit" in _branch(
            src, 'if args.no_tor and server_b32.endswith(".onion"):')

    def test_transport_selection_never_reads_a_failure(self):
        """Selection is by address or flag.  If a transport choice is ever
        made inside an exception handler or a retry, the ladder is back."""
        import ast
        xmpp = pytest.importorskip("otrv4plus_xmpp")
        tree = ast.parse(_read(xmpp.__file__))
        for node in ast.walk(tree):
            if not isinstance(node, ast.ExceptHandler):
                continue
            body = ast.dump(node)
            for chooser in ("start_tor_socks_forwarder",
                            "start_i2p_sam_forwarder"):
                if chooser in body:
                    # Re-establishing the SAME transport on retry is fine; the
                    # ladder is choosing a DIFFERENT one.  Both appearing in
                    # one handler is the shape that must not exist.
                    assert not ("start_tor_socks_forwarder" in body
                                and "start_i2p_sam_forwarder" in body), (
                        "an exception handler at line %d can reach both the "
                        "Tor and the I2P forwarder" % node.lineno)

    def test_no_latency_measurement_reaches_transport_selection(self):
        """Degraded is not failed, and neither is a reason to switch class."""
        xmpp = pytest.importorskip("otrv4plus_xmpp")
        src = _read(xmpp.__file__)
        for line in src.splitlines():
            if "use_tor =" in line or "use_i2p =" in line:
                for metric in ("latency", "rtt", "mouth_to_ear", "jitter",
                               "degraded"):
                    assert metric not in line.lower(), (
                        "transport selection reads %s: %s"
                        % (metric, line.strip()))


# --------------------------------------------------------------------------
# INV-18 -- the class is fixed, the endpoint may move if authenticated
# --------------------------------------------------------------------------

class TestTheClassIsFixedForTheCall:

    def test_the_matrix_is_an_allowlist(self):
        doc = _read(POLICY)
        i = doc.index("## 4. The transition matrix")
        matrix = doc[i:doc.index("### The two sequences")]
        for forbidden in ("I2P → TLS", "Tor → TLS", "TLS → I2P"):
            row = [ln for ln in matrix.splitlines() if ln.startswith("| " + forbidden)]
            assert row, "%s is not in the matrix" % forbidden
            assert "FORBIDDEN" in row[0], "%s is not forbidden" % forbidden
        assert "unlisted transition is forbidden, not undefined" in matrix

    def test_an_authenticated_endpoint_change_stays_allowed(self):
        """The rule is not "nothing may change"; MEDIAPATH depends on it."""
        doc = _read(POLICY)
        i = doc.index("## 4. The transition matrix")
        matrix = doc[i:doc.index("### The two sequences")]
        i2p_row = [ln for ln in matrix.splitlines()
                   if ln.startswith("| I2P → I2P")]
        assert i2p_row and "ALLOWED" in i2p_row[0]
        assert "MEDIAPATH" in i2p_row[0]

    def test_there_is_still_exactly_one_media_transport_class(self):
        """The limit recorded against INV-18.  When a second media class
        appears this fails, and the transcript binding in TRANSPORT_POLICY.md
        section 5 is what has to land with it -- not a deletion of this test.
        """
        voice = pytest.importorskip("otrv4plus_voice")
        src = _read(voice.__file__)
        # "STREAM CONNECT" is SAM's own verb, so match route mechanisms
        # rather than the word connect.
        for route in ("socks5", "SOCKS5", "PROXY_TYPE", "set_proxy",
                      "proxy_url", ".onion", "https://"):
            assert route not in src, (
                "the voice media path grew a %r route" % route)
        assert "SESSION CREATE" in src, "the media path no longer speaks SAM"

    def test_the_media_endpoint_change_is_authenticated(self):
        """An endpoint that merely arrives on the signalling channel is not
        an authenticated endpoint; it is the attack MEDIAPATH exists to
        stop.  The tag is derived from the committed epoch material and is
        compared before any state moves."""
        import inspect
        voice = pytest.importorskip("otrv4plus_voice")
        src = inspect.getsource(voice.VoiceCallSession.accept_endpoint)
        assert "_endpoint_tag" in src
        assert "hmac.compare_digest" in src, (
            "the endpoint tag is not compared in constant time")
        # Nothing may be adopted before the comparison.
        assert src.index("compare_digest") < src.index("self._peer_dest ="), (
            "the peer destination is adopted before the tag verifies")

    def test_an_endpoint_announcement_cannot_be_replayed(self):
        """Reinstating a destination the call has moved past is the same
        attack arriving in the other direction."""
        import inspect
        voice = pytest.importorskip("otrv4plus_voice")
        src = inspect.getsource(voice.VoiceCallSession.accept_endpoint)
        assert "seq <= self._endpoint_seq_seen" in src

    def test_the_transcript_binding_is_recorded_as_not_implemented(self):
        """The strong form is specified and deferred.  If it is implemented
        without this document changing, the two disagree and a reader will
        believe the document."""
        doc = _read(POLICY)
        i = doc.index("## 5. What reaches the cryptography")
        section = doc[i:doc.index("## 6.")]
        assert "not implemented" in section
        assert "wire break" in section, (
            "binding a class byte into voice key derivation is a wire break "
            "and must say so, or someone will land it as a patch release")

    def test_route_is_not_bound_into_key_derivation(self):
        doc = _read(POLICY)
        i = doc.index("## 3. Transport class and route are separate")
        section = doc[i:doc.index("## 4.")]
        assert "**not** bound into key derivation" in section
        assert "different proxies could not talk to each other" in section


# --------------------------------------------------------------------------
# INV-19 -- honest wording
# --------------------------------------------------------------------------

BANNED_PHRASES = (
    "anonymous proxy",
    "anonymising proxy",
    "anonymizing proxy",
    "proxy for anonymity",
    "anonymity through a proxy",
    "weaker encryption",
)


class TestProxiesAreNotCalledAnonymity:

    @pytest.mark.parametrize("phrase", BANNED_PHRASES)
    def test_no_document_uses_the_phrase(self, phrase):
        for path in _repo_documents():
            body = _read(path).lower()
            assert phrase not in body, (
                "%s calls a proxy anonymity (%r); a proxy operator can log, "
                "identify, inject or be compromised"
                % (os.path.basename(path), phrase))

    def test_the_policy_says_what_a_proxy_operator_can_do(self):
        doc = _read(POLICY)
        i = doc.index("## 6. Proxies, described honestly")
        section = doc[i:doc.index("## 7.")]
        for capability in ("log", "identify", "inject", "compromised"):
            assert capability in section
        assert 'never labelled "anonymous"' in section

    def test_a_proxy_mode_is_presented_inside_the_clearnet_row(self):
        doc = _read(POLICY)
        i = doc.index("## 2. The five modes")
        table = doc[i:doc.index("## 3.")]
        for mode in ("Clearnet TLS 1.3 + proxy",
                     "Clearnet TLS 1.3 + proxy chain"):
            row = [ln for ln in table.splitlines() if mode + "**" in ln]
            assert row, "%s is missing from the mode table" % mode
            assert "none" in row[0], (
                "%s claims an anonymity property" % mode)

    def test_any_future_proxy_flag_does_not_advertise_anonymity(self):
        """Fires when modes 4 and 5 are implemented, which is the point."""
        for module in ("otrv4plus_xmpp", "otrv4plus_voice"):
            mod = pytest.importorskip(module)
            for line in _read(mod.__file__).splitlines():
                if '"--proxy' not in line and "'--proxy" not in line:
                    continue
                assert "anonym" not in line.lower(), (
                    "%s: a proxy flag advertises anonymity: %s"
                    % (module, line.strip()))


class TestClearnetIsDescribedAsNotAnonymousNotAsWeak:

    def test_the_policy_separates_the_three_properties(self):
        doc = _read(POLICY)
        head = doc[:doc.index("## 2.")]
        for word in ("Encryption", "Anonymity", "Routing"):
            assert "**%s**" % word in head
        assert "not weak encryption" in head

    def test_tor_and_i2p_are_not_ranked_against_each_other(self):
        doc = _read(POLICY)
        head = doc[:doc.index("## 2.")]
        assert "different overlay networks" in head, (
            "the wording that stops Tor being 'the NSA one' and I2P 'the "
            "most secure one' has gone")

    def test_the_clearnet_row_states_the_leak_not_a_verdict(self):
        doc = _read(POLICY)
        i = doc.index("## 2. The five modes")
        table = doc[i:doc.index("## 3.")]
        row = [ln for ln in table.splitlines()
               if "**Clearnet TLS 1.3**" in ln][0]
        assert "your server sees your IP" in row
        assert "weak" not in row.lower()


# --------------------------------------------------------------------------
# The document and the implementation must not drift apart
# --------------------------------------------------------------------------

class TestTheStatusTableIsHonest:

    def test_tor_voice_is_recorded_as_a_decision_with_a_reason(self):
        doc = _read(POLICY)
        i = doc.index("## 7. Voice over Tor")
        section = doc[i:doc.index("## 8.")]
        assert "not implemented, deliberately" in doc[i:i + 120]
        assert "TCP" in section and "latency" in section
        assert "condition for revisiting" in section, (
            "a decision without a condition for revisiting is a gap wearing "
            "a decision's clothes")

    def test_tor_xmpp_is_still_marked_live_unverified(self):
        """It has been traced and unit-tested and has never carried a real
        connection.  That is its own state, and folding it into
        'implemented' is precisely the error this project has made before."""
        doc = _read(POLICY)
        i = doc.index("## 8. What exists today")
        section = doc[i:doc.index("## 9.")]
        row = [ln for ln in section.splitlines()
               if "Tor XMPP control plane" in ln][0]
        assert "LIVE-UNVERIFIED" in row

    def test_the_unimplemented_modes_say_so(self):
        doc = _read(POLICY)
        i = doc.index("## 8. What exists today")
        section = doc[i:doc.index("## 9.")]
        for capability in ("Tor voice media", "Clearnet TLS voice media",
                           "Proxy route", "Proxy chain route"):
            row = [ln for ln in section.splitlines() if capability in ln]
            assert row, "%s is missing from the status table" % capability
            assert "not implemented" in row[0], (
                "%s is claimed as implemented" % capability)

    def test_the_status_table_agrees_with_the_mode_table(self):
        doc = _read(POLICY)
        modes = doc[doc.index("## 2."):doc.index("## 3.")]
        status = doc[doc.index("## 8."):doc.index("## 9.")]
        # Mode 4 and 5 are unimplemented in both places, or in neither.
        assert ("**not implemented**" in modes) == ("not implemented" in status)

    def test_the_audit_and_the_policy_do_not_contradict(self):
        """TRANSPORT_AUDIT.md records what the code does; this records what
        it is allowed to do.  Both must agree that voice is I2P-only."""
        audit = _read(os.path.join(ROOT, "TRANSPORT_AUDIT.md"))
        assert "Voice media is I2P-only" in audit
        assert re.search(r"Tor voice media \|\s+\*\*not implemented\*\*",
                         _read(POLICY))
