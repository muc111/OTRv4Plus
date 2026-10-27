# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""L1 -- MAC-key revelation, the formal gate (docs/SECURITY_ISSUES.md, L1).

Two real engines, a real DAKE, real ratchets; every assertion is made on what
crosses the wire, read the way a third party reads it. The retirement rule
under test is SPEC §5.8 (R1 received, R2 skipped key deleted, R3 close); the
Rust side is `ratchet::l1_retirement`.

  T1  a published key re-MACs a forgery of a message really observed;
  T2  nothing is published early -- and a transcript doctored to publish
      early is caught by the same check (the mutation test);
  T3  skipped messages, across a DH step: unpublished while held, published
      once received late or deleted at close;
  T4  a published key is no longer held in the ratchet;
  T5  Make Chat Deniable: final publication, DISCONNECTED, a fresh session
      with no link to the old one;
  T6  sign-out, Wipe & Exit, quit: every session, before its keys go;
  T7  wire compatibility both ways;
  T8  no MAC key becomes a Python bytes object on any production path.

Scope: the mechanism. Formal deniability is a claim about what a simulator
can produce, and stays with the expert review the issue names.
"""
import base64
import inspect
import io
import os
import re

import pytest

import test_smp_end_to_end as E

otr = E.otr
core = pytest.importorskip("otrv4_core")
A, B, C = "alice@example.test", "bob@example.test", "carol@example.test"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DM = otr.OTRv4DataMessage


@pytest.fixture(autouse=True)
def _own_rate_limiter(monkeypatch):
    monkeypatch.setattr(otr, "_dake1_rate_limiter", otr.DAKE1RateLimiter())


def _pair(monkeypatch, rekey=None):
    if rekey is not None:
        monkeypatch.setattr(otr.OTRConstants, "REKEY_INTERVAL", rekey)
    a, b = E._manager(), E._manager()
    first, _ = a.handle_outgoing_message(B, "")
    E._relay(first, a, b, A, B)
    assert a.has_encrypted_session(B) and b.has_encrypted_session(A)
    return a, b


def _frame(wire):
    body = wire[len("?OTRv4 "):].rstrip(".")
    return DM.decode(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))


def _send(mgr, peer, text):
    wire, _ = mgr.handle_outgoing_message(peer, text)
    assert wire and wire.startswith("?OTRv4 ")
    return wire


def _published(wire):
    """The keys a wire message publishes, as anyone reads them."""
    return [bytes(k) for k in _frame(wire).revealed_mac_keys]


def _verifies(key, wire):
    """Does published [key] verify the outer MAC of [wire]?"""
    return _frame(wire).verify_mac(core.MessageMacKey.from_revealed(key))


class _Transcript:
    """Every message on the wire, in order, with who sent it and when it was
    delivered. `check_no_premature` is THE T2 predicate."""

    def __init__(self):
        self.events = []                 # ("sent", who, wire) / ("delivered", to, wire)

    def sent(self, who, wire):
        self.events.append(("sent", who, wire))
        return wire

    def delivered(self, to, wire):
        self.events.append(("delivered", to, wire))

    def check_no_premature(self):
        """Every published key verifies only messages its publisher had
        already received. Raises AssertionError otherwise."""
        received = {}                    # who -> wires they have received
        for kind, who, wire in self.events:
            if kind == "delivered":
                received.setdefault(who, []).append(wire)
                continue
            for key in _published(wire):
                for _k, sender, other in self.events:
                    if _k != "sent" or other is wire:
                        continue
                    if _verifies(key, other):
                        assert other in received.get(who, []), (
                            "%s published the key of a message it had not received" % who)


def _chat(a, b, t, rounds, lose=()):
    for i in range(rounds):
        w = t.sent("alice", _send(a, B, "a%d" % i))
        if i not in lose:
            assert b.handle_incoming_message(A, w) == ("a%d" % i).encode()
            t.delivered("bob", w)
        w = t.sent("bob", _send(b, A, "b%d" % i))
        assert a.handle_incoming_message(B, w) == ("b%d" % i).encode()
        t.delivered("alice", w)


# ── T1 ───────────────────────────────────────────────────────────────────────

class TestT1PositiveDeniability:
    # Named for what it shows (audit 2026-10-26): the published key lets a
    # third party put a valid OUTER MAC on an altered copy of a message it
    # observed. It does not make a message the receiver would decrypt; the
    # residual test below asserts that.
    def test_a_published_key_lets_anyone_mac_an_altered_copy_of_an_observed_message(self, monkeypatch):
        a, b = _pair(monkeypatch)
        observed = _send(a, B, "what was really said")
        assert b.handle_incoming_message(A, observed) == b"what was really said"
        reply = _send(b, A, "ok")
        keys = [k for k in _published(reply) if _verifies(k, observed)]
        assert keys, "the key that authenticated the observed message was published"
        # A third party holding only the transcript forges a new message
        # bearing the same, valid, MAC construction.
        forged = _frame(observed)
        forged.ciphertext = b"something the sender never sent" + bytes(16)
        published = core.MessageMacKey.from_revealed(keys[0])
        forged.mac = forged.compute_mac(published)
        assert forged.verify_mac(published)
        assert forged.ciphertext != _frame(observed).ciphertext

    def test_residual_the_receiver_refuses_a_frame_only_the_outer_mac_was_forged_for(self, monkeypatch):
        """SECURITY_ISSUES.md L1, residual: the published key forges the
        outer MAC only. AES-GCM is keyed by the message key, never
        published, so a forgery is refused -- at the position the observed
        message used (a replay) and at the next one (the AEAD tag) -- and
        the session is not disturbed by it."""
        a, b = _pair(monkeypatch)
        observed = _send(a, B, "what was really said")
        assert b.handle_incoming_message(A, observed) == b"what was really said"
        [key] = [k for k in _published(_send(b, A, "ok")) if _verifies(k, observed)]
        published = core.MessageMacKey.from_revealed(key)
        for bump in (0, 1):
            forged = _frame(observed)
            forged.message_id += bump
            forged.ciphertext = b"something the sender never sent" + bytes(16)
            forged.mac = forged.compute_mac(published)
            assert forged.verify_mac(published), "the outer MAC itself is valid"
            wire = "?OTRv4 " + base64.urlsafe_b64encode(forged.encode()).decode().rstrip("=") + "."
            assert b.handle_incoming_message(A, wire) is None, "refused, at position +%d" % bump
        assert b.handle_incoming_message(A, _send(a, B, "genuine")) == b"genuine", \
            "the forgery consumed nothing the genuine message needed"


class TestL1Residuals:
    """Residuals docs/SECURITY_ISSUES.md L1 names, asserted so they are not
    hidden (audit 2026-10-26)."""

    def test_residual_an_altered_outer_mac_costs_the_message_and_its_key_is_published(self, monkeypatch):
        """R1 commits at the AEAD tag. An attacker who alters only the outer
        MAC of a genuine message gets it refused; the genuine copy is then a
        replay, refused too; its MAC key is retired and published although
        the message was never accepted. Nothing can be verified with that
        key any more, which is why it is retired
        (docs/CRYPTOGRAPHER_QUESTIONS.md Q1 asks whether that holds in every
        interleaving). The session carries on."""
        a, b = _pair(monkeypatch)
        genuine = _send(a, B, "genuine")
        frame = _frame(genuine)
        frame.mac = bytes([frame.mac[0] ^ 0xFF]) + frame.mac[1:]
        altered = "?OTRv4 " + base64.urlsafe_b64encode(frame.encode()).decode().rstrip("=") + "."
        assert b.handle_incoming_message(A, altered) is None
        assert b.handle_incoming_message(A, genuine) is None, "now a replay"
        assert any(_verifies(k, genuine) for k in _published(_send(b, A, "r"))), "published"
        assert b.handle_incoming_message(A, _send(a, B, "next")) == b"next"


# ── T2 ───────────────────────────────────────────────────────────────────────

class TestT2NoPrematureRevelation:
    def test_a_long_conversation_with_loss_and_dh_steps_publishes_nothing_early(self, monkeypatch):
        a, b = _pair(monkeypatch, rekey=3)
        t = _Transcript()
        _chat(a, b, t, 10, lose={2, 5})
        t.check_no_premature()

    def test_a_sender_never_publishes_the_key_of_its_own_message(self, monkeypatch):
        a, b = _pair(monkeypatch, rekey=3)
        sent = []
        for i in range(8):
            w = _send(a, B, "a%d" % i)
            for k in _published(w):
                assert not any(_verifies(k, mine) for mine in sent), "a sender revealed its own key"
            sent.append(w)
            b.handle_incoming_message(A, w)
            a.handle_incoming_message(B, _send(b, A, "b%d" % i))

    def test_the_check_catches_a_transcript_that_reveals_early(self, monkeypatch):
        """Mutation: move a key Bob published AFTER receiving a late message
        into a message Bob sent BEFORE it. The predicate must fail."""
        a, b = _pair(monkeypatch)
        t = _Transcript()
        late = t.sent("alice", _send(a, B, "late"))
        later = t.sent("alice", _send(a, B, "later"))
        b.handle_incoming_message(A, later)
        t.delivered("bob", later)
        early = t.sent("bob", _send(b, A, "early"))
        b.handle_incoming_message(A, late)
        t.delivered("bob", late)
        after = t.sent("bob", _send(b, A, "after"))
        late_key = next(k for k in _published(after) if _verifies(k, late))
        t.check_no_premature()                                  # honest: passes
        doctored = _frame(early)
        doctored.revealed_field = None
        doctored.revealed_mac_keys = _published(early) + [late_key]
        forged = "?OTRv4 " + base64.urlsafe_b64encode(doctored.encode()).decode().rstrip("=") + "."
        t.events = [(k, w, forged if x is early else x) for k, w, x in t.events]
        with pytest.raises(AssertionError, match="had not received"):
            t.check_no_premature()


# ── T3 ───────────────────────────────────────────────────────────────────────

class TestT3SkippedMessages:
    def test_unpublished_while_held_across_a_dh_step_then_published_late(self, monkeypatch):
        a, b = _pair(monkeypatch, rekey=2)
        lost = _send(a, B, "held back")
        for i in range(6):                                     # several DH steps
            b.handle_incoming_message(A, _send(a, B, "a%d" % i))
            reply = _send(b, A, "b%d" % i)
            assert not any(_verifies(k, lost) for k in _published(reply)), \
                "published while the skipped key was still held"
            a.handle_incoming_message(B, reply)
        assert b.get_session(A).ratchet._rust.skipped_key_count >= 1
        assert b.handle_incoming_message(A, lost) == b"held back"
        assert any(_verifies(k, lost) for k in _published(_send(b, A, "after")))

    def test_a_skipped_key_deleted_at_close_is_published(self, monkeypatch):
        a, b = _pair(monkeypatch)
        lost = _send(a, B, "never arrives")
        b.handle_incoming_message(A, _send(a, B, "arrives"))
        assert b.make_deniable(A)
        finals = [w for _p, w in b.take_final_revelations()]
        assert any(_verifies(k, lost) for w in finals for k in _published(w))


# ── T4 ───────────────────────────────────────────────────────────────────────

class TestT4PublishedKeysAreNotHeld:
    # Renamed from TestT4Zeroization (audit 2026-10-26): it shows a published
    # key is no longer held by the ratchet, through the test-build accessor.
    # That its bytes were overwritten is the zeroize-on-drop of the queue's
    # boxes (ratchet.rs, RetiredKey), not observable from here.
    def test_a_published_key_is_no_longer_held(self, monkeypatch):
        a, b = _pair(monkeypatch)
        rust = b.get_session(A).ratchet._rust
        if not hasattr(rust, "holds_mac_key"):
            pytest.skip("needs the test build's holds_mac_key accessor")
        m = _send(a, B, "m")
        b.handle_incoming_message(A, m)
        assert rust.retired_mac_key_count >= 1
        reply = _send(b, A, "r")
        key = next(k for k in _published(reply) if _verifies(k, m))
        assert not rust.holds_mac_key(key), "published, still held in the ratchet"
        assert rust.retired_mac_key_count == 0

    def test_close_leaves_nothing_retired_nothing_skipped_and_no_ratchet(self, monkeypatch):
        a, b = _pair(monkeypatch)
        _send(a, B, "lost")
        b.handle_incoming_message(A, _send(a, B, "got"))
        session = b.get_session(A)
        rust = session.ratchet._rust
        session.close_with_revelation(announce=True)
        assert rust.retired_mac_key_count == 0 and rust.skipped_key_count == 0
        assert rust.closing
        b.end_session(A, "test")
        assert session.ratchet is None


# ── T5 ───────────────────────────────────────────────────────────────────────

class TestT5PublishChatKeys:
    # Renamed (audit 2026-10-26): "unlinked" was broader than the test --
    # it shows the new session shares no key with the old one; both
    # handshakes are signed by the same identities (SPEC §10.1).
    def test_final_publication_disconnect_and_a_fresh_session_sharing_no_key(self, monkeypatch):
        a, b = _pair(monkeypatch)
        history = []
        for i in range(3):
            w = _send(a, B, "a%d" % i)
            history.append(w)
            b.handle_incoming_message(A, w)
        old_session = b.get_session(A)
        assert b.make_deniable(A)
        assert not b.has_encrypted_session(A), "torn down"
        finals = [w for p, w in b.take_final_revelations() if p == A]
        assert finals, "a final message went out"
        published = [k for w in finals for k in _published(w)]
        for w in history:
            assert any(_verifies(k, w) for k in published), "every received message forgeable"
        assert all(_frame(w).flags & DM.FLAG_IGNORE_UNREADABLE for w in finals)
        # The peer reads the final message: DISCONNECTED ends its side too,
        # and it publishes what IT retired in return.
        for w in finals:
            a.handle_incoming_message(B, w)
        assert not a.has_encrypted_session(B)
        assert a.take_final_revelations(), "the peer's own closing publication"
        # A fresh session, cryptographically independent of the old one.
        first, _ = b.handle_outgoing_message(A, "")
        E._relay(first, b, a, B, A)
        assert a.has_encrypted_session(B) and b.has_encrypted_session(A)
        assert b.get_session(A) is not old_session
        new = _send(b, A, "new session")                    # the new initiator first
        assert not any(_verifies(k, new) for k in published), "no link to the old transcript"
        assert a.handle_incoming_message(B, new) == b"new session"
        back = _send(a, B, "and back")
        assert b.handle_incoming_message(A, back) == b"and back"

    def test_no_session_no_action(self, monkeypatch):
        a, _b = _pair(monkeypatch)
        assert a.make_deniable(C) is False


# ── T6 ───────────────────────────────────────────────────────────────────────

def _three(monkeypatch):
    a, b = _pair(monkeypatch)
    c = E._manager()
    first, _ = a.handle_outgoing_message(C, "")
    E._relay(first, a, c, A, C)
    assert a.has_encrypted_session(C)
    got = {}
    for mgr, peer, name in ((b, A, B), (c, A, C)):
        w, _ = mgr.handle_outgoing_message(peer, "to alice")
        a.handle_incoming_message(name, w)
        got[name] = w
    return a, b, c, got


class TestT6SignOutWipeQuit:
    @pytest.mark.parametrize("teardown", ["sign_out", "wipe"])
    def test_every_session_publishes_before_its_keys_go(self, monkeypatch, teardown):
        a, b, c, got = _three(monkeypatch)
        if teardown == "sign_out":
            a.clear_all_sessions("logout")
        else:
            a.wipe("wipe and exit")
        assert not a.sessions, "every session gone"
        finals = a.take_final_revelations()
        for peer in (B, C):
            mine = [w for p, w in finals if p == peer]
            assert mine, "no closing message for %s" % peer
            keys = [k for w in mine for k in _published(w)]
            assert any(_verifies(k, got[peer]) for k in keys)
            assert DM.FLAG_IGNORE_UNREADABLE & _frame(mine[-1]).flags

    @pytest.mark.parametrize("ending", ["terminate", "failure"])
    def test_a_session_ending_by_termination_or_failure_publishes_too(self, monkeypatch, ending):
        """SPEC §5.8 Close: "an error or expiry" closes the same way. These
        two paths reach the publication only through `_cleanup_resources`
        (audit 2026-10-26: removing that call failed no test)."""
        a, b = _pair(monkeypatch)
        got = _send(a, B, "m")
        b.handle_incoming_message(A, got)
        session = b.get_session(A)
        if ending == "terminate":
            session.terminate("test")
        else:
            session._cleanup_failed_session()
        finals = [w for _p, w in b.take_final_revelations()]
        assert any(_verifies(k, got) for w in finals for k in _published(w))

    def test_the_peers_closing_message_after_our_end_starts_no_handshake(self, monkeypatch):
        """Bob answers Alice's DISCONNECTED by publishing his own keys. By then
        Alice has no session: the frame is IGNORE_UNREADABLE, so it is dropped
        quietly -- not taken for a lost session, which would start a DAKE for
        a session both sides ended."""
        a, b = _pair(monkeypatch)
        b.handle_incoming_message(A, _send(a, B, "m"))
        a.clear_all_sessions("logout")
        for _p, w in a.take_final_revelations():
            b.handle_incoming_message(A, w)
        answers = [w for _p, w in b.take_final_revelations()]
        assert answers, "Bob published his side"
        for w in answers:
            assert a.handle_incoming_message(B, w) is None
        assert not a.take_orphan_data(B), "no recovery handshake for an ended session"

    def test_offline_the_keys_are_still_retired_and_wiped(self, monkeypatch):
        a, b, c, _got = _three(monkeypatch)
        rusts = [a.get_session(B).ratchet._rust, a.get_session(C).ratchet._rust]
        a.clear_all_sessions("logout")
        a.take_final_revelations()                          # dropped: never sent
        assert all(r.retired_mac_key_count == 0 and r.skipped_key_count == 0 for r in rusts)

    def test_the_bridge_sends_them_before_the_transport_goes(self):
        from android_bridge.app import OtrApp
        app = _read("android_bridge", "app.py")
        shutdown = app[app.index("    def shutdown(self) -> None:"):]
        shutdown = shutdown[:shutdown.index("\n    @property")]
        assert shutdown.index('clear_all_sessions("shutdown")') \
            < shutdown.index("self._send_final_revelations()") < shutdown.index("self.disconnect()")
        wipe = _read("android_bridge", "app_wipe.py")
        body = wipe[wipe.index("    def wipe(self, delete_account"):]
        assert body.index("crypto = self.wipe_crypto()") \
            < body.index("self._send_final_revelations()") < body.index("closer()")
        term = _read("client", "otrv4plus_xmpp.py")
        assert term.index('clear_all_sessions("xmpp client shutdown")') \
            < term.index("self._send_final_revelations()\n", term.index('clear_all_sessions("xmpp client shutdown")'))
        assert callable(OtrApp._send_final_revelations)

    # Renamed (audit 2026-10-26): it never tested an offline transport, and
    # the bridge no longer drops closing messages offline -- it keeps them
    # (tests/test_deniable_confirmation.py::test_offline_at_the_press_they_go_when_it_is_back).
    def test_the_bridge_sends_each_closing_message_once(self, monkeypatch):
        from android_bridge.app import OtrApp
        a, b, c, _got = _three(monkeypatch)
        a.clear_all_sessions("logout")

        class _Wire:
            is_connected = True
            def __init__(self):
                self.sent = []
            def send(self, peer, text):
                self.sent.append(peer)

        app = OtrApp.__new__(OtrApp)
        app._engine, app._transport = a, _Wire()
        assert app._send_final_revelations() == 2
        assert sorted(app._transport.sent) == [B, C]
        assert app._send_final_revelations() == 0, "each handed out once"


# ── T7 ───────────────────────────────────────────────────────────────────────

class TestT7WireCompatibility:
    def test_a_peer_reading_the_field_by_shape_only_accepts_real_keys(self, monkeypatch):
        a, b = _pair(monkeypatch)
        b.handle_incoming_message(A, _send(a, B, "m"))
        reply = _send(b, A, "r")
        keys = _published(reply)
        assert keys and all(len(k) == DM.REVEALED_MAC_KEY_LEN for k in keys)
        assert all(any(x for x in k) for k in keys), "real keys, not zero placeholders"
        # The message itself is unaffected by what the field carries.
        assert a.handle_incoming_message(B, reply) == b"r"

    def test_the_field_is_outside_what_the_mac_covers(self, monkeypatch):
        """Why a receiver that ignores the field -- one that "expects zeros" --
        reads a message carrying real keys exactly as before: the outer MAC
        does not cover the field, so its content cannot change whether a
        message authenticates."""
        a, b = _pair(monkeypatch)
        b.handle_incoming_message(A, _send(a, B, "m"))
        real = _frame(_send(b, A, "r"))
        assert real.revealed_mac_keys
        bare = _frame(_send(b, A, "r2"))
        for frame in (real, bare):
            region = frame.auth_region()
            stripped = DM.decode(frame.encode())
            stripped.revealed_field, stripped.revealed_mac_keys = None, []
            assert stripped.auth_region() == region
        # And the receiver: the same message with the field emptied still
        # authenticates and decrypts.
        real.revealed_field, real.revealed_mac_keys = None, []
        wire = "?OTRv4 " + base64.urlsafe_b64encode(real.encode()).decode().rstrip("=") + "."
        assert a.handle_incoming_message(B, wire) == b"r"

    def test_a_peer_implementing_it_accounts_for_every_key_it_is_shown(self, monkeypatch):
        a, b = _pair(monkeypatch)
        b.handle_incoming_message(A, _send(a, B, "m"))
        a.handle_incoming_message(B, _send(b, A, "r"))
        s = a.get_session(B)
        assert s.revealed_mac_keys_verified >= 1
        assert s.revealed_mac_keys_unaccounted == 0


# ── T8 ───────────────────────────────────────────────────────────────────────

def _read(*parts):
    with io.open(os.path.join(ROOT, *parts), encoding="utf-8") as fh:
        return fh.read()


class TestT8NoMacKeyBytesInPython:
    def test_the_ratchet_hands_over_the_field_and_handles_only(self, monkeypatch):
        a, b = _pair(monkeypatch)
        rust = b.get_session(A).ratchet._rust
        out = rust.encrypt(b"x")
        assert isinstance(out["reveal_field"], bytes)
        assert "reveal_mac_keys" not in out
        assert type(out["mac_key"]).__name__ == "MessageMacKey"
        for name in ("retire_all", "encrypt_final"):
            doc = getattr(type(rust), name).__doc__ or ""
            assert "never the keys" in doc or "reveal_field" in doc or "retired" in doc

    def test_a_mac_key_handle_has_no_bytes(self):
        handle = core.MessageMacKey.from_revealed(bytes(range(64)))
        public = [n for n in dir(handle) if not n.startswith("_")]
        assert set(public) <= {"seal", "verify", "matches", "zeroize", "destroyed",
                               "from_revealed"}, public
        with pytest.raises(TypeError):
            bytes(handle)

    def test_no_production_path_unpacks_the_field_into_keys(self):
        """The field is framed as it came from Rust; only tests and a
        verifier read keys out of it (`parse_revealed_field`)."""
        for parts in (("client", "otrv4+.py"), ("android_bridge", "app_deniable.py"),
                      ("android_bridge", "app.py"), ("client", "otrv4plus_xmpp.py")):
            src = _read(*parts)
            uses = [m.start() for m in re.finditer(r"parse_revealed_field\(", src)]
            defs = [m.start() for m in re.finditer(r"def parse_revealed_field\(", src)]
            assert len(uses) == len(defs), parts
        engine = _read("client", "otrv4+.py")
        seal = engine[engine.index("    def _seal_data_message("):]
        seal = seal[:seal.index("\n    def ", 10)]
        assert "dmsg.revealed_field = OTRv4DataMessage.check_revealed_field(reveal_field)" in seal
        assert "revealed_mac_keys =" not in seal

    def test_the_deniable_paths_move_wire_text_only(self):
        src = _read("android_bridge", "app_deniable.py")
        assert "mac_key" not in src.replace("revealed_mac_keys", "")
        sig = inspect.signature(otr.EnhancedSessionManager.take_final_revelations)
        assert "Tuple[str, str]" in str(sig.return_annotation)
