"""The trade courier carries blobs and nothing else.

`MONERO_ESCROW_AUDIT.md` rejected putting Monero's cryptography in the Rust
core: `monero-serai` is yanked, `monero-oxide`'s multisig is FROST and cannot
interoperate with `monero-wallet-cli`, native multisig is experimental and off
by default, and FCMP++ removes CLSAG. What shipped instead is a courier — the
client relays opaque base64 between two wallets it does not run.

That makes the whole security argument rest on two things, and both are
asserted here:

  * the client never becomes a wallet (INV-25), and
  * a trade never touches an unverified or changed peer (INV-26).

The second half of that is the one worth stating twice. `is_smp_verified` is
checked on EVERY message in both directions, not once when the trade opens,
and the peer's fingerprint is re-checked with it. A trade that verified at
09:00 and is still running at 14:00 has been re-checked on every message in
between; the alternative is a five-hour window in which a session teardown or
a fingerprint change goes unnoticed while blobs keep flowing.

Enforces INV-25 and INV-26.
"""

import base64
import os

import pytest

trade = pytest.importorskip("otrv4plus_trade")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class Party:
    """One side of a trade, with the four injected dependencies stubbed.

    Deliberately not a real client: the manager takes `send`, `notify`,
    `verified` and `fingerprint` and touches nothing else, and a stub makes
    that surface visible. `deliver` hands one party's outbound messages to
    the other, which is the whole of the transport.
    """

    def __init__(self, name, verified=True, fingerprint=None):
        self.name = name
        self.out = []
        self.log = []
        self.verified = verified
        self.fingerprints = {}
        self.send_ok = True
        self._default_fp = fingerprint
        self.mgr = trade.TradeManager(
            send=self._send,
            notify=self.log.append,
            verified=self._verified,
            fingerprint=self._fingerprint,
        )

    def _send(self, peer, verb, payload):
        if not self.send_ok:
            return False
        self.out.append((verb, payload))
        return True

    def _verified(self, peer):
        if isinstance(self.verified, Exception):
            raise self.verified
        return self.verified

    def _fingerprint(self, peer):
        if self._default_fp is not None:
            return self._default_fp
        return self.fingerprints.get(peer, "FP:" + peer)

    def deliver(self, other, only=None):
        """Hand `other`'s pending outbound messages to this party."""
        for verb, payload in other.out:
            if only and verb != only:
                continue
            self.mgr.handle_control(
                other.name, trade.TRADE_PREFIX + verb + ":" + payload)
        other.out.clear()

    def said(self, needle):
        return any(needle in line for line in self.log)


@pytest.fixture
def pair():
    a, b = Party("alice"), Party("bob")
    a.fingerprints["bob"] = "FP:bob"
    b.fingerprints["alice"] = "FP:alice"
    return a, b


@pytest.fixture
def active(pair):
    """A trade both sides have agreed to."""
    a, b = pair
    a.mgr.start("bob", "0.5 XMR for 120 EUR, SEPA")
    b.deliver(a)
    b.mgr.accept("alice")
    a.deliver(b)
    assert a.mgr.trades["bob"].state == trade.ACTIVE
    assert b.mgr.trades["alice"].state == trade.ACTIVE
    return a, b


#: An active trade is not swept for age alone -- multisig setup over I2P is
#: slow -- so the "old but not idle" case needs a number well past the
#: proposal timeout.
PROPOSAL_PLUS_A_DAY = 24 * 3600.0


def a_blob(size=512):
    """`size` random bytes, base64'd. Random on purpose: a courier that
    happened to work only for printable input would pass on fixed data."""
    return base64.b64encode(os.urandom(size)).decode()


class TestTheHappyPath:

    def test_a_trade_reaches_active_on_both_sides(self, active):
        a, b = active
        assert a.mgr.trades["bob"].role == "proposer"
        assert b.mgr.trades["alice"].role == "responder"

    def test_both_sides_agree_on_the_trade_id(self, active):
        a, b = active
        assert a.mgr.trades["bob"].trade_id == b.mgr.trades["alice"].trade_id

    def test_a_blob_arrives_byte_for_byte(self, active):
        a, b = active
        blob = a_blob(900)
        a.mgr.send_blob("bob", blob)
        b.deliver(a)
        assert b.said(blob), "the blob was altered in transit"
        assert b.mgr.trades["alice"].blobs_received == 1

    def test_the_receiver_is_told_it_has_not_been_checked(self, active):
        """The courier's whole limitation, stated at the moment it matters."""
        a, b = active
        a.mgr.send_blob("bob", a_blob(64))
        b.deliver(a)
        assert b.said("has not checked what it means")

    def test_confirmation_is_reported_as_hearsay_not_proof(self, active):
        a, b = active
        a.mgr.confirm("bob")
        b.deliver(a)
        b.mgr.confirm("alice")
        a.deliver(b)
        assert a.mgr.trades["bob"].both_confirmed()
        assert a.said("not proof of anything on the chain")

    def test_a_decline_closes_the_trade_on_both_sides(self, pair):
        a, b = pair
        a.mgr.start("bob", "terms")
        b.deliver(a)
        b.mgr.decline("alice", "not today")
        a.deliver(b)
        assert a.mgr.trades == {}
        assert b.mgr.trades == {}


class TestTheSmpGate:
    """INV-26. Not once at the start — every message, both directions."""

    def test_an_unverified_peer_cannot_be_offered_a_trade(self, pair):
        a, _ = pair
        a.verified = False
        with pytest.raises(trade.TradeError, match="not SMP-verified"):
            a.mgr.start("bob", "terms")
        assert a.mgr.trades == {}

    def test_verification_lost_mid_trade_stops_the_next_blob(self, active):
        """The window this closes: a trade that verified hours ago, whose
        session has since been torn down and re-established without SMP."""
        a, _ = active
        a.verified = False
        with pytest.raises(trade.TradeError, match="not SMP-verified"):
            a.mgr.send_blob("bob", a_blob(64))

    def test_verification_lost_mid_trade_stops_an_inbound_blob(self, active):
        a, b = active
        blob = a_blob(64)
        a.mgr.send_blob("bob", blob)
        b.verified = False
        b.deliver(a)
        assert not b.said(blob), "an inbound blob was accepted unverified"
        assert b.mgr.trades["alice"].blobs_received == 0

    def test_a_predicate_that_raises_counts_as_unverified(self, pair):
        """Fail-closed, matching INV-12. A predicate that throws on failure
        as readily as on success would otherwise report an actively failed
        session as verified."""
        a, _ = pair
        a.verified = RuntimeError("engine is confused")
        with pytest.raises(trade.TradeError, match="not SMP-verified"):
            a.mgr.start("bob", "terms")

    @pytest.mark.parametrize("call", [
        lambda m: m.accept("alice"),
        lambda m: m.decline("alice"),
        lambda m: m.send_blob("alice", base64.b64encode(b"x").decode()),
        lambda m: m.confirm("alice"),
    ])
    def test_every_command_is_gated_not_just_the_first(self, active, call):
        _, b = active
        b.verified = False
        with pytest.raises(trade.TradeError, match="not SMP-verified"):
            call(b.mgr)


class TestFingerprintBinding:
    """A trade is bound to a key, never to a JID or an I2P destination."""

    def test_a_changed_fingerprint_cancels_the_trade(self, active):
        a, _ = active
        a.fingerprints["bob"] = "FP:someone-else"
        with pytest.raises(trade.TradeError, match="fingerprint"):
            a.mgr.send_blob("bob", a_blob(64))
        assert a.mgr.trades == {}, "the trade survived a key change"

    def test_it_is_never_re_pinned(self, active):
        """Matching INV-11: a mismatch keeps the old pin and stops. Silently
        adopting the new key is how a MITM inherits a trade."""
        a, _ = active
        a.fingerprints["bob"] = "FP:someone-else"
        with pytest.raises(trade.TradeError):
            a.mgr.send_blob("bob", a_blob(64))
        with pytest.raises(trade.TradeError, match="no trade"):
            a.mgr.send_blob("bob", a_blob(64))

    def test_a_vanished_fingerprint_is_a_changed_one(self, active):
        a, _ = active
        a.fingerprints["bob"] = None
        with pytest.raises(trade.TradeError, match="fingerprint"):
            a.mgr.confirm("bob")

    def test_a_trade_cannot_open_without_a_fingerprint(self, pair):
        a, _ = pair
        a.fingerprints["bob"] = None
        with pytest.raises(trade.TradeError, match="no fingerprint"):
            a.mgr.start("bob", "terms")


class TestReplayAndOrdering:

    def test_a_repeated_message_is_refused(self, active):
        a, b = active
        a.mgr.send_blob("bob", a_blob(64))
        frame = trade.TRADE_PREFIX + a.out[0][0] + ":" + a.out[0][1]
        b.mgr.handle_control("alice", frame)
        assert b.mgr.trades["alice"].blobs_received == 1
        b.mgr.handle_control("alice", frame)          # replay
        assert b.mgr.trades["alice"].blobs_received == 1, "replay accepted"
        assert b.said("out-of-order")

    def test_a_replayed_accept_cannot_reopen_a_cancelled_trade(self, pair):
        """The concrete reason sequence numbers are here: an ACCEPT captured
        and replayed after a CANCEL would otherwise put the proposer back
        into ACTIVE with no counterparty."""
        a, b = pair
        a.mgr.start("bob", "terms")
        b.deliver(a)
        b.mgr.accept("alice")
        accept_frame = trade.TRADE_PREFIX + b.out[0][0] + ":" + b.out[0][1]
        a.deliver(b)
        a.mgr.cancel("bob")
        assert a.mgr.trades == {}
        a.mgr.handle_control("bob", accept_frame)
        assert a.mgr.trades == {}, "a replayed ACCEPT reopened the trade"

    def test_a_message_for_a_different_trade_id_is_refused(self, active):
        a, b = active
        a.mgr.send_blob("bob", a_blob(64))
        verb, payload = a.out[0]
        parts = payload.split("|")
        parts[1] = "f" * 32
        b.mgr.handle_control(
            "alice", trade.TRADE_PREFIX + verb + ":" + "|".join(parts))
        assert b.mgr.trades["alice"].blobs_received == 0
        assert b.said("trade id does not match")

    def test_a_wrong_trade_id_does_not_burn_the_sequence_window(self, active):
        """Order of checks matters: if the sequence advanced before the id
        was compared, an attacker could push our counter past the legitimate
        peer's next message and wedge the trade."""
        a, b = active
        before = b.mgr.trades["alice"].recv_seq
        a.mgr.send_blob("bob", a_blob(64))
        verb, payload = a.out[0]
        parts = payload.split("|")
        parts[1] = "f" * 32
        parts[2] = "9999"
        b.mgr.handle_control(
            "alice", trade.TRADE_PREFIX + verb + ":" + "|".join(parts))
        assert b.mgr.trades["alice"].recv_seq == before


class TestTheTermsAreTheTrade:

    def test_an_init_whose_hash_does_not_match_is_refused(self, pair):
        a, b = pair
        a.mgr.start("bob", "0.5 XMR for 120 EUR")
        verb, payload = a.out[0]
        parts = payload.split("|")
        parts[4] = "0" * 64                     # wrong digest
        b.mgr.handle_control(
            "alice", trade.TRADE_PREFIX + verb + ":" + "|".join(parts))
        assert b.mgr.trades == {}
        assert b.said("terms hash does not match")

    def test_accepting_different_terms_cancels_rather_than_reconciles(self, pair):
        """Two sides looking at different text is not something to paper
        over: the terms ARE the trade."""
        a, b = pair
        a.mgr.start("bob", "0.5 XMR for 120 EUR")
        b.deliver(a)
        b.mgr.trades["alice"].terms_digest = trade.terms_hash("5 XMR for free")
        b.mgr.accept("alice")
        a.deliver(b)
        assert a.mgr.trades == {}, "the trade continued on disputed terms"
        assert a.said("different terms")

    def test_terms_survive_the_round_trip(self, pair):
        a, b = pair
        terms = "0.5 XMR for 120 EUR — SEPA, 2-of-3, arbiter carol@x.i2p"
        a.mgr.start("bob", terms)
        b.deliver(a)
        assert b.mgr.trades["alice"].terms == terms

    def test_empty_terms_are_refused(self, pair):
        a, _ = pair
        with pytest.raises(trade.TradeError, match="say what the trade is"):
            a.mgr.start("bob", "   ")

    def test_terminal_escapes_in_terms_are_stripped(self, pair):
        """Terms come from the peer and are printed to a terminal."""
        a, b = pair
        a.mgr.start("bob", "pay me \x1b[2J\x07 now\r\nsecond line")
        b.deliver(a)
        got = b.mgr.trades["alice"].terms
        assert "\x1b" not in got and "\x07" not in got
        assert "\r" not in got and "\n" not in got


class TestBlobsAreOpaque:

    def test_the_blob_is_never_decoded_into_anything(self, active):
        """Round-trips arbitrary bytes, including things that look like
        structured data, because the courier must not care."""
        a, b = active
        for raw in (b"\x00" * 300, b"Multisig" + os.urandom(500),
                    b"{" * 200, bytes(range(256))):
            blob = base64.b64encode(raw).decode()
            a.mgr.send_blob("bob", blob)
            b.deliver(a)
            assert b.said(blob)

    @pytest.mark.parametrize("bad", [
        "not base64!", "AAAA$$$$", "AA=AA", "\x00AAA", "AAA AAA=x",
    ])
    def test_a_non_base64_blob_is_refused(self, active, bad):
        a, _ = active
        with pytest.raises(trade.TradeError):
            a.mgr.send_blob("bob", bad)

    def test_an_empty_blob_is_refused(self, active):
        a, _ = active
        for empty in ("", "   ", base64.b64encode(b"").decode()):
            with pytest.raises(trade.TradeError, match="nothing to send"):
                a.mgr.send_blob("bob", empty)

    def test_a_blob_at_the_limit_is_accepted(self, active):
        a, b = active
        blob = base64.b64encode(os.urandom(trade.MAX_BLOB_BYTES)).decode()
        a.mgr.send_blob("bob", blob)
        b.deliver(a)
        assert b.mgr.trades["alice"].blobs_received == 1

    def test_the_limit_still_fits_the_receiver_rate_budget(self):
        """MAX_BLOB_BYTES is a constraint imposed by ANOTHER file.

        Raising it in isolation is the bug this catches: a blob that
        fragments into more stanzas than the receiver's limiter allows in one
        window gets throttled halfway, and the user cannot tell a throttled
        trade from a failed one. That is how file transfer broke twice before
        `absorb_transfer_message` existed.

        Derived from the XMPP client's own constants rather than restated, so
        a change on either side is caught by whichever is now wrong.
        """
        xmpp = pytest.importorskip("otrv4plus_xmpp")
        budget = xmpp._RATE_MAX
        per_stanza = 6000            # send_otr_fragmented's MAX_FRAGMENT

        # base64 of the blob (~4/3), then encryption and the frame's own
        # base64 (~4/3 again) -> ~1.9x the raw size on the wire.
        wire_bytes = trade.MAX_BLOB_BYTES * 1.9
        stanzas = -(-wire_bytes // per_stanza)     # ceil

        assert stanzas <= budget * 0.6, (
            "a %d byte blob needs about %d stanzas, and the receiver only "
            "allows %d per window. Either lower MAX_BLOB_BYTES or give trade "
            "traffic an allowance the way file transfer has one."
            % (trade.MAX_BLOB_BYTES, stanzas, budget)
        )

    def test_a_blob_over_the_limit_is_refused(self, active):
        """The cap is a rate-limit constraint: a blob that half-arrives and
        is then throttled is worse than one never sent."""
        a, _ = active
        blob = base64.b64encode(os.urandom(trade.MAX_BLOB_BYTES + 1)).decode()
        with pytest.raises(trade.TradeError):
            a.mgr.send_blob("bob", blob)

    def test_an_oversized_inbound_blob_is_refused_before_decoding(self, active):
        """Checked on the ENCODED length. Decoding a huge field to discover
        it is too big is the allocation the sender wanted."""
        a, b = active
        a.mgr.send_blob("bob", a_blob(64))
        verb, payload = a.out[0]
        parts = payload.split("|")
        parts[3] = "A" * (trade.MAX_BLOB_BYTES * 8)
        b.mgr.handle_control(
            "alice", trade.TRADE_PREFIX + verb + ":" + "|".join(parts))
        assert b.mgr.trades["alice"].blobs_received == 0

    def test_whitespace_in_a_pasted_blob_is_tolerated(self, active):
        """Wallets wrap their output. Someone pasting a wrapped blob should
        not have to un-wrap it by hand."""
        a, b = active
        raw = os.urandom(400)
        wrapped = "\n".join(base64.b64encode(raw).decode()[i:i + 60]
                            for i in range(0, 600, 60))
        a.mgr.send_blob("bob", wrapped)
        b.deliver(a)
        assert b.said(base64.b64encode(raw).decode())


class TestTheStateMachine:

    def test_a_blob_before_acceptance_is_refused(self, pair):
        a, _ = pair
        a.mgr.start("bob", "terms")
        with pytest.raises(trade.TradeError, match="PROPOSED, not ACTIVE"):
            a.mgr.send_blob("bob", a_blob(64))

    def test_the_proposer_cannot_accept_their_own_proposal(self, pair):
        a, _ = pair
        a.mgr.start("bob", "terms")
        with pytest.raises(trade.TradeError, match="PROPOSED, not OFFERED"):
            a.mgr.accept("bob")

    def test_only_one_trade_per_peer(self, pair):
        a, _ = pair
        a.mgr.start("bob", "first")
        with pytest.raises(trade.TradeError, match="already open"):
            a.mgr.start("bob", "second")

    def test_a_second_inbound_proposal_is_refused(self, active):
        a, b = active
        a.mgr.trades.pop("bob")
        a.mgr.start("bob", "another")
        b.deliver(a)
        assert b.said("already open")

    def test_cancel_works_from_any_state(self, pair):
        a, b = pair
        a.mgr.start("bob", "terms")
        a.mgr.cancel("bob")
        assert a.mgr.trades == {}

    def test_cancel_drops_the_trade_even_if_telling_them_fails(self, active):
        """A trade the user abandoned must not linger in a state where the
        next inbound blob would be accepted."""
        a, _ = active
        a.send_ok = False
        a.mgr.cancel("bob")
        assert a.mgr.trades == {}

    def test_a_send_failure_is_reported_not_swallowed(self, active):
        a, _ = active
        a.send_ok = False
        with pytest.raises(trade.TradeError, match="never sent in the clear"):
            a.mgr.send_blob("bob", a_blob(64))


class TestMalformedInput:

    @pytest.mark.parametrize("payload", [
        "", "1", "1|", "1|abc|1", "x|" + "a" * 32 + "|1",
        "1|" + "g" * 32 + "|1", "1|" + "a" * 31 + "|1",
        "1|" + "a" * 32 + "|0", "1|" + "a" * 32 + "|-1",
        "1|" + "a" * 32 + "|notanumber",
    ])
    def test_a_malformed_header_is_consumed_and_dropped(self, active, payload):
        _, b = active
        consumed = b.mgr.handle_control(
            "alice", trade.TRADE_PREFIX + "BLOB:" + payload)
        assert consumed, "a malformed message fell through and became chat"
        assert b.mgr.trades["alice"].blobs_received == 0

    def test_an_unknown_verb_is_consumed_and_dropped(self, active):
        _, b = active
        assert b.mgr.handle_control(
            "alice", trade.TRADE_PREFIX + "PAYOUT:1|" + "a" * 32 + "|1")

    def test_a_future_protocol_version_is_refused_not_guessed_at(self, active):
        a, b = active
        a.mgr.send_blob("bob", a_blob(64))
        verb, payload = a.out[0]
        parts = payload.split("|")
        parts[0] = "99"
        b.mgr.handle_control(
            "alice", trade.TRADE_PREFIX + verb + ":" + "|".join(parts))
        assert b.mgr.trades["alice"].blobs_received == 0
        assert b.said("protocol v99")

    def test_a_non_trade_message_is_not_consumed(self, active):
        _, b = active
        assert b.mgr.handle_control("alice", "hello there") is False
        assert b.mgr.handle_control("alice", "?OTRv4-FILE:OFFER:x") is False


class TestNothingIsKept:

    def test_clear_empties_everything(self, active):
        a, _ = active
        assert a.mgr.clear() == 1
        assert a.mgr.trades == {}
        assert a.mgr.clear() == 0

    def test_a_stale_proposal_is_swept(self, pair):
        a, _ = pair
        a.mgr.start("bob", "terms")
        a.mgr.trades["bob"].created -= trade.PROPOSAL_TIMEOUT_S + 1
        assert a.mgr.sweep() == 1
        assert a.mgr.trades == {}

    def test_an_idle_active_trade_is_swept(self, active):
        a, _ = active
        a.mgr.trades["bob"].last_activity -= trade.TRADE_IDLE_TIMEOUT_S + 1
        assert a.mgr.sweep() == 1

    def test_an_active_trade_is_not_swept_for_being_old(self, active):
        """Multisig setup over I2P is slow. Age alone is not staleness."""
        a, _ = active
        a.mgr.trades["bob"].created -= PROPOSAL_PLUS_A_DAY
        assert a.mgr.sweep() == 0
        assert "bob" in a.mgr.trades

    def test_the_module_never_writes_to_disk(self):
        """INV-25. Trade state that survived a restart would mean trusting a
        file about who the counterparty was and how far the trade had got."""
        with open(os.path.join(ROOT, "otrv4plus_trade.py"),
                  encoding="utf-8") as fh:
            source = fh.read()
        for forbidden in ("open(", "os.write", "pathlib", "json.dump",
                          "pickle", "shelve", "sqlite3", "tempfile"):
            assert forbidden not in source, (
                "otrv4plus_trade.py now touches persistence via %r; trade "
                "state is in memory only" % forbidden
            )


class TestTradeOutputNeverReachesTheSessionLog:
    """A blob is sensitive: the 2021 Monero disclosure included recovery of
    the view secret key by an eavesdropper on the multisig setup exchange.

    The session log is an allowlist of line shapes (INV-03), so a `[trade]`
    line is redacted by construction rather than by a rule someone wrote.
    That is the right answer and it is worth pinning, because the obvious
    "improvement" is to add `trade` to `_LOG_SAFE_TAGS` so the transcript
    reads better — which would write every blob and every set of terms to
    disk in plaintext.
    """

    @staticmethod
    @pytest.fixture(scope="class")
    def xmpp():
        return pytest.importorskip("otrv4plus_xmpp")

    def test_trade_is_not_a_safe_log_tag(self, xmpp):
        assert "trade" not in xmpp._LOG_SAFE_TAGS, (
            "adding `trade` to the safe tags writes multisig blobs and trade "
            "terms to the session log in plaintext"
        )

    @pytest.mark.parametrize("line", [
        "[trade] blob #1 from bob (900 bytes) for trade abcdef12",
        "[trade]   terms: 0.5 XMR for 120 EUR, SEPA",
        "[trade] proposed abcdef12 to bob@example.i2p",
    ])
    def test_trade_lines_are_redacted(self, xmpp, line):
        written = xmpp._log_line_for_file(line)
        assert written.startswith("<unlogged line:"), written

    def test_a_blob_itself_is_redacted(self, xmpp):
        blob = base64.b64encode(os.urandom(600)).decode()
        written = xmpp._log_line_for_file(blob)
        assert blob[:40] not in written, "a multisig blob reached the log"


class TestItIsNotAWallet:
    """INV-25, asserted against the source because it is a claim about what
    the module does NOT contain."""

    @staticmethod
    @pytest.fixture(scope="class")
    def source():
        with open(os.path.join(ROOT, "otrv4plus_trade.py"),
                  encoding="utf-8") as fh:
            return fh.read()

    @pytest.mark.parametrize("forbidden", [
        "subprocess", "socket", "requests", "urllib", "http",
        "spend_key", "view_key", "secret_key", "private_key", "seed",
        "mnemonic", "derive", "sign", "wallet_rpc",
    ])
    def test_no_wallet_or_network_identifiers(self, source, forbidden):
        """Asserted over the *identifiers*, not the raw text.

        The module says the word "Monero" in the line telling the user where
        to paste a blob, and it says "wallet" throughout explaining what it
        is not. Grepping the source would fail on its own documentation. What
        matters is whether any name in the code can reach a wallet, a daemon
        or a key -- so this walks the AST instead.
        """
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
            "otrv4plus_trade.py now has the identifier(s) %r. It is a "
            "courier: it opens no wallet, speaks to no daemon, and derives "
            "no key." % offenders
        )

    def test_it_imports_nothing_that_could_reach_a_wallet(self, source):
        imports = [l.strip() for l in source.splitlines()
                   if l.startswith(("import ", "from "))]
        assert imports == [
            "import base64", "import hashlib", "import re", "import secrets",
            "import time", "from typing import Callable, Dict, List, Optional",
        ], "the courier's import list changed: %r" % imports

    def test_it_ships_no_arbitrator_key(self, source):
        """The maintainer does not act as an arbitrator. Users bring their
        own third party; there is no code path that would let this client
        hold one of three keys."""
        for forbidden in ("arbitrator_key", "ARBITRATOR_KEY", "escrow_key"):
            assert forbidden not in source

    def test_the_disclaimer_says_what_it_is(self, source):
        text = trade.DISCLAIMER.lower()
        for claim in ("holds no funds", "no keys", "verifies nothing",
                      "does not act", "arbitrator"):
            assert claim in text
