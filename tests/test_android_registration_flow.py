# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Create account, from the button down to the transport.

`tests/test_registration.py` has the rules and `tests/test_android_registration.py`
has the stream. This has the controller: what the Register button actually
calls, what it does to the stage the screen renders, and the two things it must
not do.

IT MUST NOT SIGN THE USER IN. Registration and authentication are two
operations. Folded together, a registration that succeeded and a login that
failed would have one outcome between them and the user could not tell which
half went wrong -- on a network where the second half can take four minutes,
that is the difference between retyping a password and creating a second
account.

IT MUST NOT DISTURB A LIVE SESSION. Somebody may be connected while this runs
-- creating a second account for a friend on their phone is the obvious case --
and the registration stream is a different stream. It is closed on the way out,
and the controller's own transport is left exactly where it was.
"""

import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import otrv4plus_registration as reg
from android_bridge.connection import ConnectionController, SamProbe
from android_bridge.settings import ConnectionProfile

JID = "alice@xmpp-elite.i2p"
SERVER = "hq4t24b7vkllfbk55e5xfocqhfi7hxprwc47zyuilbg6wgzikidq.b32.i2p"


class FakeApp:
    def __init__(self):
        self._transport = None

    def receive_message(self, peer, payload):
        raise AssertionError(
            "a pre-authentication stanza reached the engine")

    def note_presence(self, peer, online, show=""):
        pass

    def note_presence_lost(self):
        pass

    def set_event_sink(self, sink):
        pass


class FakeTransport:
    """Accepts every keyword the real one does; see the binding test below."""

    def __init__(self, profile, password, *, on_payload, on_state=None,
                 on_presence=None, on_subscription_request=None,
                 subscription_policy=None, client_factory=None,
                 forwarder=None, outcome=None, raises=None):
        self.profile = profile
        self.password = password
        self.on_payload = on_payload
        self.on_state = on_state
        self.outcome = outcome or (reg.OK, reg.CODES[reg.OK])
        self.raises = raises
        self.is_connected = False
        self.closed = False
        self.registered = False
        self.connected_count = 0

    def register_account(self):
        self.registered = True
        if self.raises is not None:
            raise self.raises
        return self.outcome

    def connect(self):
        self.connected_count += 1
        self.is_connected = True

    def close(self):
        self.closed = True
        self.is_connected = False


def build(*, outcome=None, raises=None, probe=None, profile=None):
    made = {"transports": []}

    def factory(p, password, **kw):
        t = FakeTransport(p, password, outcome=outcome, raises=raises, **kw)
        made["transports"].append(t)
        made["transport"] = t
        return t

    app = FakeApp()
    ctl = ConnectionController(
        app, profile or ConnectionProfile(jid=JID, server=SERVER),
        transport_factory=factory,
        prober=lambda _p, **_kw: probe or SamProbe(True, "ok", "fine", "3.1"))
    made["app"] = app
    return ctl, made


# ── it worked ────────────────────────────────────────────────────────────────

class TestTheAccountIsCreated:

    def test_it_reports_ok(self):
        ctl, _ = build()
        got = ctl.register("correct-horse-battery")
        assert got["ok"] is True
        assert got["code"] == reg.OK

    def test_the_stage_says_registered_and_not_connected(self):
        """Its own stage. "disconnected" looks identical on screen and means
        the opposite thing to somebody who has just pressed Create account."""
        ctl, _ = build()
        ctl.register("correct-horse-battery")
        assert ctl.stage == "registered"

    def test_registered_is_a_declared_stage(self):
        assert "registered" in ConnectionController.STAGES

    def test_it_does_not_sign_the_user_in(self):
        ctl, made = build()
        ctl.register("correct-horse-battery")
        assert made["transport"].connected_count == 0
        assert ctl.status()["connected"] is False

    def test_the_detail_is_the_sentence_for_the_code(self):
        ctl, _ = build()
        assert ctl.register("correct-horse-battery")["detail"] == \
            reg.CODES[reg.OK]


# ── it did not ───────────────────────────────────────────────────────────────

class TestRefusals:

    def test_a_taken_username_reaches_the_screen_as_conflict(self):
        ctl, _ = build(outcome=("conflict", reg.CODES["conflict"]))
        got = ctl.register("correct-horse-battery")
        assert got["ok"] is False
        assert got["code"] == "conflict"
        assert ctl.stage == "failed"

    def test_a_server_with_no_registration_says_unsupported(self):
        ctl, _ = build(outcome=("unsupported", reg.CODES["unsupported"]))
        assert ctl.register("correct-horse-battery")["code"] == "unsupported"

    def test_no_router_is_reported_without_spending_the_timeout(self):
        """The same first gate connect has. A registration attempt with no
        router is four minutes of nothing."""
        ctl, made = build(probe=SamProbe(False, "sam_refused", "no router",
                                         ""))
        got = ctl.register("correct-horse-battery")
        assert got["ok"] is False
        assert got["code"] == "network"
        assert made["transports"] == [], "a transport was built anyway"

    def test_an_exception_that_escapes_is_classified_not_raised(self):
        """`register_account` is documented not to raise. Documented not to is
        not the same as cannot, and the alternative on a handset is a
        PyException with a stanza in it."""
        ctl, _ = build(raises=RuntimeError("boom"))
        got = ctl.register("correct-horse-battery")
        assert got["ok"] is False
        assert got["code"] in reg.CODES

    def test_a_transport_that_will_not_build_is_not_a_network_error(self):
        def factory(*_a, **_kw):
            raise ImportError("slixmpp missing")

        ctl = ConnectionController(
            FakeApp(), ConnectionProfile(jid=JID, server=SERVER),
            transport_factory=factory,
            prober=lambda _p, **_kw: SamProbe(True, "ok", "fine", "3.1"))
        got = ctl.register("correct-horse-battery")
        assert got["ok"] is False
        assert got["code"] == "unknown", (
            "a packaging fault sent the user to look at their router")

    def test_every_code_it_can_return_is_one_the_ui_knows(self):
        for code in ("conflict", "not_acceptable", "unsupported", "timeout",
                     "network", "cancelled", "unknown"):
            ctl, _ = build(outcome=(code, reg.CODES[code]))
            assert ctl.register("correct-horse-battery")["code"] in reg.CODES


# ── what it must not touch ───────────────────────────────────────────────────

class TestItLeavesTheSessionAlone:

    def test_the_registration_stream_is_closed(self):
        ctl, made = build()
        ctl.register("correct-horse-battery")
        assert made["transport"].closed is True

    def test_it_is_closed_after_a_refusal_too(self):
        ctl, made = build(outcome=("conflict", reg.CODES["conflict"]))
        ctl.register("correct-horse-battery")
        assert made["transport"].closed is True

    def test_it_is_closed_when_register_account_raises(self):
        ctl, made = build(raises=RuntimeError("boom"))
        ctl.register("correct-horse-battery")
        assert made["transport"].closed is True

    def test_a_live_session_survives_a_registration_beside_it(self):
        """`_release_transport` would have torn this down. Registering an
        account for somebody else's phone must not hang up the user."""
        ctl, made = build()
        ctl.connect("correct-horse-battery")
        live = made["transport"]
        ctl.register("another-password-entirely")
        assert made["app"]._transport is live
        assert live.closed is False
        assert live.is_connected is True

    def test_the_registration_transport_is_not_installed_in_the_app(self):
        ctl, made = build()
        ctl.register("correct-horse-battery")
        assert made["app"]._transport is None

    def test_nothing_inbound_is_routed_into_the_engine(self):
        """FakeApp.receive_message raises. A pre-authentication stanza given
        a route into the engine is the reason this is checked at all."""
        ctl, made = build()
        ctl.register("correct-horse-battery")
        made["transport"].on_payload("bob@x.i2p", "?OTRv4+ frame")


class TestOnlyOneThingAtATime:

    def test_a_registration_during_a_connect_is_refused(self):
        ctl, _ = build()
        ctl._connecting = True
        got = ctl.register("correct-horse-battery")
        assert got["ok"] is False
        assert got["code"] == "already_connecting"

    def test_the_flag_is_released_afterwards(self):
        ctl, _ = build()
        ctl.register("correct-horse-battery")
        assert ctl.register("correct-horse-battery")["ok"] is True

    def test_the_flag_is_released_after_a_failure(self):
        ctl, _ = build(raises=RuntimeError("boom"))
        ctl.register("correct-horse-battery")
        assert ctl._connecting is False


# ── the password ─────────────────────────────────────────────────────────────

class TestThePasswordGoesNowhereItShouldNot:

    PASSWORD = "correct-horse-battery-staple"

    def test_it_is_not_in_the_result(self):
        ctl, _ = build()
        got = ctl.register(self.PASSWORD)
        assert self.PASSWORD not in repr(got)

    def test_it_is_not_in_the_status(self):
        ctl, _ = build()
        ctl.register(self.PASSWORD)
        assert self.PASSWORD not in repr(ctl.status())

    def test_it_is_not_in_the_diagnostic_report(self):
        ctl, _ = build()
        ctl.register(self.PASSWORD)
        assert self.PASSWORD not in ctl.diagnostic_report()

    def test_the_inputs_line_reports_it_as_present_only(self):
        ctl, _ = build()
        ctl.register(self.PASSWORD)
        text = ctl.inputs_text()
        assert self.PASSWORD not in text
        assert "present" in text


class TestTheReportSaysWhatHappenedWithoutSayingWhoTo:

    def test_the_attempt_is_recorded(self):
        ctl, _ = build(outcome=("conflict", reg.CODES["conflict"]))
        ctl.register("correct-horse-battery")
        text = ctl.diagnostic_report()
        assert "registration" in text
        assert "conflict" in text

    def test_the_account_is_not(self):
        ctl, _ = build()
        ctl.register("correct-horse-battery")
        text = ctl.diagnostic_report()
        assert "alice" not in text
        assert "xmpp-elite" not in text


# ── the fake cannot agree with a mistake ─────────────────────────────────────

class TestTheFakeMatchesTheRealTransport:

    def test_the_real_transport_has_register_account(self):
        from android_bridge.transport import XmppTransport

        assert hasattr(XmppTransport, "register_account")

    def test_it_takes_no_arguments_beyond_self(self):
        """The credentials come from the profile it was built with, so that a
        transport cannot register one account while being configured for
        another."""
        import inspect

        from android_bridge.transport import XmppTransport

        params = inspect.signature(XmppTransport.register_account).parameters
        assert list(params) == ["self"]

    def test_the_fake_accepts_every_keyword_the_real_one_does(self):
        import inspect

        from android_bridge.transport import XmppTransport

        real = set(inspect.signature(XmppTransport.__init__).parameters)
        mine = set(inspect.signature(FakeTransport.__init__).parameters)
        assert real - mine == set(), real - mine
