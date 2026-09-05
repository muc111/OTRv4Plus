"""`/tip` relays a Monero address and does nothing else.

The feature is small — one string over one TLV — and the risk is entirely in
what it might grow into. Three things are asserted here, and they are the
three that would matter if this ever went wrong:

  * **it stays a relay** (INV-25): no wallet, no RPC, no network, no key, and
    no validation of the address, because validating would mean holding an
    opinion about Monero's address format that goes stale at a hard fork;
  * **it never acts for an unverified peer** (INV-26), in either direction —
    a *response* matters as much as a request, because a response is a string
    the client is about to show the user as somewhere to send money;
  * **no inbound message arms local input capture** (INV-06). The brief for
    this feature asked for an interactive prompt on an inbound request with
    no address configured. That is the mechanism `_apply_tofu` once used for
    `_pending[peer] = "smp_secret"`, and it is not implemented: an
    unanswerable request is reported and the user replies with an explicit
    `/tipreply`.

Enforces INV-06, INV-25 and INV-26.
"""

import json
import os
import tempfile

import pytest

tip = pytest.importorskip("otrv4plus_tip")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

#: Shape only — 95 chars starting with 4. Nothing in the module knows or
#: cares that this is what a Monero address looks like.
ADDRESS = "4" + "B" * 94


class Party:
    def __init__(self, name, store=None):
        self.name = name
        self.out = []
        self.log = []
        self.verified = True
        self.send_ok = True
        self.mgr = tip.TipManager(
            send=self._send, notify=self.log.append,
            verified=self._verified, store_path=store)

    def _send(self, peer, raw):
        if not self.send_ok:
            return False
        self.out.append(raw)
        return True

    def _verified(self, peer):
        if isinstance(self.verified, Exception):
            raise self.verified
        return self.verified

    def deliver(self, other):
        for raw in other.out:
            self.mgr.handle_tlv(other.name, raw)
        other.out.clear()

    def said(self, needle):
        return any(needle in line for line in self.log)

    def sent_payloads(self):
        return [json.loads(raw.decode()) for raw in self.out]


@pytest.fixture
def store():
    with tempfile.TemporaryDirectory() as d:
        yield os.path.join(d, "xmr.json")


@pytest.fixture
def pair(store):
    return Party("alice"), Party("bob", store)


class TestTheHappyPath:

    def test_a_request_is_answered_from_the_stored_address(self, pair):
        alice, bob = pair
        bob.mgr.set_address(ADDRESS)
        alice.mgr.request("bob", "0.5", "thanks for the call test")
        bob.deliver(alice)
        alice.deliver(bob)
        assert alice.said(ADDRESS)
        assert alice.mgr.received["bob"]["address"] == ADDRESS
        assert alice.mgr.received["bob"]["amount"] == "0.5"

    def test_the_note_reaches_the_other_side(self, pair):
        alice, bob = pair
        bob.mgr.set_address(ADDRESS)
        alice.mgr.request("bob", "0.5", "for the soak test")
        bob.deliver(alice)
        assert bob.said("for the soak test")

    def test_the_amount_is_echoed_back(self, pair):
        alice, bob = pair
        bob.mgr.set_address(ADDRESS)
        alice.mgr.request("bob", "1.25")
        bob.deliver(alice)
        assert bob.sent_payloads()[0]["amount"] == "1.25"

    def test_the_reader_is_told_the_client_sends_nothing(self, pair):
        """The single most important line in the feature: `/tip` is a name
        for asking, not for paying."""
        alice, bob = pair
        bob.mgr.set_address(ADDRESS)
        alice.mgr.request("bob", "0.5")
        bob.deliver(alice)
        alice.deliver(bob)
        assert alice.said("this client sends nothing")


class TestTheSmpGate:
    """INV-26, in both directions."""

    def test_an_unverified_peer_cannot_be_asked(self, pair):
        alice, _ = pair
        alice.verified = False
        with pytest.raises(tip.TipError, match="not SMP-verified"):
            alice.mgr.request("bob", "0.5")
        assert alice.out == []

    def test_an_unverified_request_is_not_answered(self, pair):
        alice, bob = pair
        bob.mgr.set_address(ADDRESS)
        alice.mgr.request("bob", "0.5")
        bob.verified = False
        bob.deliver(alice)
        assert bob.out == [], "an address was sent to an unverified peer"

    def test_an_unverified_response_is_not_displayed(self, pair):
        """The direction that matters more: a response is a string the
        client is about to show the user as somewhere to send money."""
        alice, bob = pair
        bob.mgr.set_address(ADDRESS)
        alice.mgr.request("bob", "0.5")
        bob.deliver(alice)
        alice.verified = False
        alice.deliver(bob)
        assert not alice.said(ADDRESS)
        assert alice.mgr.received == {}

    def test_a_predicate_that_raises_counts_as_unverified(self, pair):
        """Fail-closed, matching INV-12 and INV-26."""
        alice, _ = pair
        alice.verified = RuntimeError("engine is confused")
        with pytest.raises(tip.TipError, match="not SMP-verified"):
            alice.mgr.request("bob", "0.5")

    def test_tipreply_is_gated_too(self, pair):
        alice, bob = pair
        alice.mgr.request("bob", "0.5")
        bob.deliver(alice)
        bob.mgr.set_address(ADDRESS)
        bob.verified = False
        with pytest.raises(tip.TipError, match="not SMP-verified"):
            bob.mgr.reply("alice")


class TestNoRemoteInputCapture:
    """INV-06. The brief asked for an interactive prompt here; it is not
    implemented, and this is what stands in its place."""

    def test_an_unanswerable_request_is_reported_and_nothing_is_sent(self, pair):
        alice, bob = pair                      # bob has no address configured
        alice.mgr.request("bob", "0.5")
        bob.deliver(alice)
        assert bob.out == []
        assert bob.said("no address configured")
        assert "alice" in bob.mgr.pending_requests

    def test_the_user_answers_with_an_explicit_command(self, pair):
        alice, bob = pair
        alice.mgr.request("bob", "0.5")
        bob.deliver(alice)
        bob.mgr.set_address(ADDRESS)
        bob.mgr.reply("alice")
        alice.deliver(bob)
        assert alice.said(ADDRESS)
        assert bob.mgr.pending_requests == {}

    def test_replying_with_no_request_is_refused(self, pair):
        _, bob = pair
        bob.mgr.set_address(ADDRESS)
        with pytest.raises(tip.TipError, match="no unanswered tip request"):
            bob.mgr.reply("alice")

    def test_replying_with_no_address_is_refused(self, pair):
        alice, bob = pair
        alice.mgr.request("bob", "0.5")
        bob.deliver(alice)
        with pytest.raises(tip.TipError, match="no address configured"):
            bob.mgr.reply("alice")

    def test_the_module_never_reads_from_stdin(self):
        """The structural half. `input()`, `getpass` or a read on stdin
        anywhere in this module would mean an inbound TLV could reach a
        prompt, which is the defect INV-06 exists for."""
        import ast
        with open(os.path.join(ROOT, "otrv4plus_tip.py"),
                  encoding="utf-8") as fh:
            source = fh.read()
        names = set()
        for node in ast.walk(ast.parse(source)):
            if isinstance(node, ast.Name):
                names.add(node.id)
            elif isinstance(node, ast.Attribute):
                names.add(node.attr)
        for forbidden in ("input", "getpass", "stdin", "readline",
                          "raw_input"):
            assert forbidden not in names, (
                "otrv4plus_tip.py references %r. An inbound TLV must never "
                "be able to reach a prompt for the user's next line "
                "(INV-06)." % forbidden
            )


class TestTheAddressIsOpaque:

    @pytest.mark.parametrize("weird", [
        "4" + "B" * 94,                # a plausible one
        "8" + "C" * 105,               # integrated, longer
        "not-an-address",              # not one at all
        "9" * 200,                     # unusual but within the cap
        "0",                           # one character
    ])
    def test_anything_round_trips_unaltered(self, pair, weird):
        """No validation, on purpose: an opinion about Monero's address
        format is an opinion that starts rejecting valid addresses at a
        hard fork."""
        alice, bob = pair
        bob.mgr.set_address(weird)
        alice.mgr.request("bob", "0.5")
        bob.deliver(alice)
        alice.deliver(bob)
        assert alice.mgr.received["bob"]["address"] == weird

    def test_an_address_with_a_space_is_refused_as_a_paste_error(self, pair):
        """The one shape that is rejected, and not as validation: a space
        means two things were pasted, and sending the first half of an
        address is worse than refusing."""
        _, bob = pair
        with pytest.raises(tip.TipError, match="space"):
            bob.mgr.set_address("4BBB CCC")

    def test_terminal_escapes_are_stripped(self, pair):
        """Peer-supplied and printed to a terminal."""
        alice, bob = pair
        bob.mgr.set_address("4\x1b[2J\x07BBB")
        alice.mgr.request("bob", "0.5")
        bob.deliver(alice)
        alice.deliver(bob)
        got = alice.mgr.received["bob"]["address"]
        assert "\x1b" not in got and "\x07" not in got

    def test_an_over_long_address_is_truncated_not_rejected(self, pair):
        _, bob = pair
        saved = bob.mgr.set_address("4" * (tip.MAX_ADDRESS_LEN + 500))
        assert len(saved) == tip.MAX_ADDRESS_LEN


class TestAmounts:

    @pytest.mark.parametrize("good", ["0.5", "1", "100000",
                                      "0.000000000001", "12345678901234567890"])
    def test_plain_decimals_pass(self, good):
        assert tip.normalise_amount(good) == good

    @pytest.mark.parametrize("bad", [
        "1e9", "0x10", "inf", "nan", "-1", "+1", "1,5", "", "   ",
        "0.5 XMR", "١٢٣", "1.2.3", "." , "0." ,
    ])
    def test_anything_else_is_refused(self, bad):
        """`float()` would accept `1e9`, `inf` and `nan`, and none of them
        belongs in a `monero:` URI or in a line someone reads to decide what
        to send."""
        with pytest.raises(tip.TipError):
            tip.normalise_amount(bad)

    @pytest.mark.parametrize("hostile", [
        "1&recipient_name=evil",
        "1?tx_description=drain",
        "1 OR 1",
        "\u0661\u0662\u0663",          # Arabic-Indic digits: `\d` accepts these
        "1e9",
    ])
    def test_a_hostile_amount_never_reaches_the_uri(self, pair, monkeypatch,
                                                    hostile):
        """The peer controls the amount field in a response.

        It is displayed either way -- that is their claim about what they
        asked for -- but it must not be concatenated into a URI a wallet
        scanner will parse. Asserted on what `render_qr` is CALLED with,
        because the URI is encoded into the image and never printed: a test
        that grepped the output for "monero:" would pass no matter what the
        code did.
        """
        seen = []

        def spy(address, amount=""):
            seen.append((address, amount))
            return None

        monkeypatch.setattr(tip, "render_qr", spy)
        alice, _ = pair
        alice.mgr.handle_tlv("bob", json.dumps({
            "cmd": "address_response", "address": ADDRESS,
            "amount": hostile,
        }).encode())
        assert alice.mgr.received["bob"]["address"] == ADDRESS
        assert seen, "no QR was attempted at all"
        assert seen[0][1] == "", (
            "the peer-supplied amount %r reached the URI" % hostile)

    def test_a_good_amount_does_reach_the_uri(self, pair, monkeypatch):
        """The other half: rejecting everything would pass the test above
        and lose the feature."""
        seen = []
        monkeypatch.setattr(tip, "render_qr",
                            lambda a, amount="": seen.append(amount))
        alice, _ = pair
        alice.mgr.handle_tlv("bob", json.dumps({
            "cmd": "address_response", "address": ADDRESS, "amount": "0.5",
        }).encode())
        assert seen == ["0.5"]


class TestMalformedInput:

    @pytest.mark.parametrize("raw", [
        b"", b"not json", b"[]", b'"a string"', b"123", b"null",
        b'{"cmd":"address_response"}',              # no address
        b'{"cmd":"address_response","address":""}',
        b'{"cmd":"unknown_command"}',
        b'{}',
        b"\xff\xfe not utf-8",
    ])
    def test_it_never_raises_out_of_the_tlv_handler(self, pair, raw):
        """Called from the engine's TLV router: a feature must not be able
        to break a session."""
        alice, _ = pair
        alice.mgr.handle_tlv("bob", raw)        # must not raise
        assert alice.mgr.received == {}

    def test_an_oversized_payload_is_refused(self, pair):
        alice, _ = pair
        alice.mgr.handle_tlv("bob", b"x" * (tip.MAX_PAYLOAD_BYTES + 1))
        assert alice.said("over the")

    def test_an_unknown_command_is_dropped_in_silence(self, pair):
        """Forward compatibility: a peer running a newer client is not an
        error, and must not produce a line saying it is."""
        alice, _ = pair
        alice.mgr.handle_tlv(
            "bob", b'{"cmd":"address_revocation","address":"x"}')
        assert alice.log == []

    def test_a_send_failure_is_reported_not_silent(self, pair):
        alice, _ = pair
        alice.send_ok = False
        with pytest.raises(tip.TipError, match="never sent in the clear"):
            alice.mgr.request("bob", "0.5")

    def test_a_failed_auto_answer_says_the_address_was_not_sent(self, pair):
        alice, bob = pair
        bob.mgr.set_address(ADDRESS)
        alice.mgr.request("bob", "0.5")
        bob.send_ok = False
        bob.deliver(alice)
        assert bob.said("NOT sent in the clear")


class TestPersistence:

    def test_the_address_survives_a_restart(self, store):
        first = Party("bob", store)
        first.mgr.set_address(ADDRESS)
        assert Party("bob", store).mgr.address == ADDRESS

    def test_the_store_is_0600(self, store):
        Party("bob", store).mgr.set_address(ADDRESS)
        assert oct(os.stat(store).st_mode & 0o777) == "0o600", (
            "your Monero address sits next to your OTR identity; a "
            "world-readable file links the two for anyone on the box"
        )

    def test_clearing_removes_the_file(self, store):
        party = Party("bob", store)
        party.mgr.set_address(ADDRESS)
        party.mgr.forget_address()
        assert not os.path.exists(store)
        assert Party("bob", store).mgr.address is None

    def test_a_corrupt_store_disables_the_feature_rather_than_the_client(self, store):
        with open(store, "w") as fh:
            fh.write("{ this is not json")
        assert Party("bob", store).mgr.address is None

    def test_a_peer_address_is_never_written(self, store):
        """The RECEIVER's store is the one to look at, and it needs to exist:
        a receiver with no store cannot fail this test whatever the code
        does, which is how the first version of it passed a mutant that
        wrote peer addresses to disk."""
        # tempfile, not tmp_path: conftest stubs `pwd`, which pytest's
        # tmp_path factory calls.
        with tempfile.TemporaryDirectory() as d:
            their_store = os.path.join(d, "xmr.json")
            alice, bob = Party("alice", their_store), Party("bob", store)
            alice.mgr.set_address("4" + "Z" * 94)   # so alice HAS a store file
            bob.mgr.set_address(ADDRESS)
            alice.mgr.request("bob", "0.5")
            bob.deliver(alice)
            alice.deliver(bob)
            assert alice.mgr.received["bob"]["address"] == ADDRESS

            with open(their_store, encoding="utf-8") as fh:
                on_disk = fh.read()
        assert ADDRESS not in on_disk, "a peer's address was written to disk"
        assert "bob" not in on_disk
        assert list(json.loads(on_disk)) == ["xmr_address"]

    def test_clear_drops_session_state_but_keeps_configuration(self, pair):
        """Your own address is configuration and lives on disk. A peer's is
        session state and goes with the session (INV-24)."""
        alice, bob = pair
        bob.mgr.set_address(ADDRESS)
        alice.mgr.request("bob", "0.5")
        bob.deliver(alice)
        alice.deliver(bob)
        assert alice.mgr.clear() == 1
        assert alice.mgr.received == {}
        assert bob.mgr.address == ADDRESS


class TestTheQrCode:

    def test_the_uri_is_the_monero_scheme(self):
        assert tip.monero_uri(ADDRESS, "0.5") == \
            "monero:" + ADDRESS + "?tx_amount=0.5"

    def test_no_amount_means_no_query_string(self):
        assert tip.monero_uri(ADDRESS) == "monero:" + ADDRESS

    def test_it_fits_a_phone_terminal(self):
        """A QR you have to scroll is not scannable."""
        segno = pytest.importorskip("segno")
        rendered = tip.render_qr(ADDRESS, "0.5")
        assert rendered
        lines = rendered.rstrip("\n").split("\n")
        assert len(lines) <= 30, "%d rows will not fit a handset" % len(lines)

    def test_a_missing_library_is_not_a_failure(self, pair, monkeypatch):
        """`segno` is a nicety, and the address is what the user needs."""
        import builtins
        real_import = builtins.__import__

        def no_segno(name, *args, **kwargs):
            if name == "segno":
                raise ImportError("no segno")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", no_segno)
        assert tip.render_qr(ADDRESS, "0.5") is None

        alice, bob = pair
        bob.mgr.set_address(ADDRESS)
        alice.mgr.request("bob", "0.5")
        bob.deliver(alice)
        alice.deliver(bob)
        assert alice.said(ADDRESS), "the address was withheld with no QR"
        assert alice.said("pip install segno")


class TestItIsStillARelay:
    """INV-25, the same assertions the trade courier carries."""

    @staticmethod
    @pytest.fixture(scope="class")
    def source():
        with open(os.path.join(ROOT, "otrv4plus_tip.py"),
                  encoding="utf-8") as fh:
            return fh.read()

    #: Substrings, so `spend_key_bytes` is caught as readily as `spend_key`.
    #: Library names are NOT here -- `requests` would match the perfectly
    #: legitimate `pending_requests`, and `test_the_import_list_cannot_reach_
    #: a_network` pins the libraries exactly, which is the stronger check.
    @pytest.mark.parametrize("forbidden", [
        "subprocess", "socket", "urlopen",
        "spend_key", "view_key", "private_key", "mnemonic", "derive",
        "sign", "wallet", "rpc", "validate",
    ])
    def test_no_wallet_or_network_identifiers(self, source, forbidden):
        import ast
        names = set()
        for node in ast.walk(ast.parse(source)):
            if isinstance(node, ast.Name):
                names.add(node.id.lower())
            elif isinstance(node, ast.Attribute):
                names.add(node.attr.lower())
            elif isinstance(node, ast.FunctionDef):
                names.add(node.name.lower())
                names.update(a.arg.lower() for a in node.args.args)
        offenders = sorted(n for n in names if forbidden in n)
        assert not offenders, (
            "otrv4plus_tip.py now has %r. It relays one string: it opens no "
            "wallet, speaks to no daemon, and validates nothing."
            % offenders)

    def test_the_import_list_cannot_reach_a_network(self, source):
        imports = [l.strip() for l in source.splitlines()
                   if l.startswith(("import ", "from "))]
        assert imports == [
            "import json", "import os", "import re", "import tempfile",
            "import time",
            "from typing import Callable, Dict, Optional",
        ], "the tip module's import list changed: %r" % imports

    def test_the_disclaimer_says_it_sends_no_money(self):
        text = tip.DISCLAIMER.lower()
        for claim in ("sends no money", "verifies nothing", "subaddress"):
            assert claim in text


class TestTipOutputNeverReachesTheSessionLog:
    """A Monero address is public, but a *log of who asked whom for which
    address* is a record of who paid whom, which is not.

    The session log is an allowlist of line shapes (INV-03), so `[tip]` lines
    are redacted by construction. Pinned because the obvious "improvement" is
    to add `tip` to `_LOG_SAFE_TAGS` so the transcript reads better.
    """

    @staticmethod
    @pytest.fixture(scope="class")
    def xmpp():
        return pytest.importorskip("otrv4plus_xmpp")

    def test_tip_is_not_a_safe_log_tag(self, xmpp):
        assert "tip" not in xmpp._LOG_SAFE_TAGS, (
            "adding `tip` to the safe tags writes every address and every "
            "amount asked for to the session log in plaintext"
        )

    @pytest.mark.parametrize("line", [
        "\U0001f510 [tip] bob's XMR address for 0.5 XMR:",
        "\U0001f4ec " + ADDRESS,
        "\u2705 [tip] sent your address to bob@example.i2p",
    ])
    def test_tip_lines_are_redacted(self, xmpp, line):
        written = xmpp._log_line_for_file(line)
        assert ADDRESS[:40] not in written
        assert "bob" not in written


class TestTheEngineHook:
    """The TLV type and the registry live in `otrv4+.py`; this module only
    names the type. They must agree, and the registry must stay narrow."""

    @staticmethod
    @pytest.fixture(scope="class")
    def engine():
        return pytest.importorskip("otrv4plus")

    def test_the_tlv_type_matches_the_engine(self, engine):
        assert tip.TIP_TLV_TYPE == engine.OTRv4TLV.TIP == 0x0020

    def test_it_does_not_collide_with_an_allocated_type(self, engine):
        allocated = {engine.OTRv4TLV.PADDING, engine.OTRv4TLV.DISCONNECTED,
                     engine.OTRv4TLV.SMP_MSG_1, engine.OTRv4TLV.SMP_MSG_2,
                     engine.OTRv4TLV.SMP_MSG_3, engine.OTRv4TLV.SMP_MSG_4,
                     engine.OTRv4TLV.SMP_ABORT, engine.OTRv4TLV.SMP_MSG_1Q,
                     engine.OTRv4TLV.EXTRA_SYMMETRIC_KEY}
        assert engine.OTRv4TLV.TIP not in allocated
        assert engine.OTRv4TLV.TIP > max(allocated)

    @pytest.mark.parametrize("forbidden", [0x0000, 0x0001, 0x0002, 0x0006,
                                           0x0009, 0x0021, 0xFFFF])
    def test_the_registry_refuses_every_other_type(self, engine, forbidden):
        """Not a general extension point. Anything wider is how a forwarding
        hook becomes an unreviewed second protocol on the session."""
        with pytest.raises(ValueError):
            engine.register_tlv_handler(forbidden, lambda p, v: None)

    def test_send_tlv_refuses_engine_owned_types(self, engine):
        mgr = engine.EnhancedSessionManager(engine.OTRConfig(test_mode=True))
        for owned in (engine.OTRv4TLV.SMP_MSG_1,
                      engine.OTRv4TLV.DISCONNECTED):
            with pytest.raises(ValueError):
                mgr.send_tlv("peer", owned, b"x")

    def test_send_tlv_is_fail_closed_with_no_session(self, engine):
        """It must not open a session, queue, or fall back to plaintext: a
        feature TLV that started a DAKE would hand a peer a handshake they
        never asked for."""
        mgr = engine.EnhancedSessionManager(engine.OTRConfig(test_mode=True))
        assert mgr.send_tlv("nobody@example.i2p", 0x0020, b"{}") is None
        assert mgr.sessions == {} or "nobody@example.i2p" not in mgr.sessions

    def test_a_tip_tlv_survives_the_payload_codec(self, engine):
        value = b'{"cmd":"address_request","amount":"0.5"}'
        tlv = engine.OTRv4TLV(engine.OTRv4TLV.TIP, value)
        wire = engine.OTRv4Payload("", [tlv]).encode(add_padding=True)
        back = engine.OTRv4Payload.decode(wire)
        carried = [t for t in back.tlvs if t.type == engine.OTRv4TLV.TIP]
        assert len(carried) == 1 and carried[0].value == value

    def test_a_tlv_only_message_is_still_length_padded(self, engine):
        """Traffic analysis: a fixed-length TLV-only message would be
        distinguishable from chat. PADDING is added on encode and discarded
        on decode, so the variation is on the wire, not in the payload."""
        tlv = engine.OTRv4TLV(engine.OTRv4TLV.TIP, b'{"cmd":"x"}')
        sizes = {len(engine.OTRv4Payload("", [tlv]).encode(add_padding=True))
                 for _ in range(40)}
        assert len(sizes) > 5, "TLV-only messages have a constant length"
