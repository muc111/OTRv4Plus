# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Rooms through the controller: the shape Kotlin reads, and the local gate.

`tests/test_muc_rules.py` has the rules and `tests/test_android_rooms.py` has
the stream. This has the layer between: one result shape for every operation,
a local check before an I2P round trip is spent, and a trace that records what
was done without recording where or by whom.

WHY ONE SHAPE. Every method here returns `{ok, code, detail, value}` and none
of them raises. The caller is Kotlin through Chaquopy, where an exception
arrives as a PyException whose message is the only thing that survives -- and a
MUC error's message carries the room, the service and the nickname.
"""

import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import otrv4plus_muc as muc
from android_bridge.connection import ConnectionController, SamProbe
from android_bridge.settings import ConnectionProfile

JID = "alice@xmpp-elite.i2p"
SERVER = "hq4t24b7vkllfbk55e5xfocqhfi7hxprwc47zyuilbg6wgzikidq.b32.i2p"
MUC_SERVICE = "rooms.xmpp-elite.i2p"
ROOM = "general@" + MUC_SERVICE
NICK = "alice"


class FakeApp:
    def __init__(self):
        self._transport = None

    def receive_message(self, peer, payload):
        pass

    def note_presence(self, peer, online, show=""):
        pass

    def note_presence_lost(self):
        pass

    def set_event_sink(self, sink):
        pass


class FakeTransport:
    """Answers `(code, detail, value)` the way the real one does."""

    def __init__(self, profile, password, *, on_payload, on_state=None,
                 on_presence=None, on_subscription_request=None,
                 subscription_policy=None, client_factory=None,
                 forwarder=None, answer=None, raises=None):
        self.profile = profile
        self.is_connected = False
        self.closed = False
        self.calls = []
        self.answer = answer or ("ok", muc.CODES["ok"], {})
        self.raises = raises

    def connect(self):
        self.is_connected = True

    def close(self):
        self.closed = True
        self.is_connected = False

    def _room(self, name, *args):
        self.calls.append((name,) + args)
        if self.raises is not None:
            raise self.raises
        return self.answer

    def discover_services(self):
        return self._room("discover_services")

    def discover_rooms(self, service):
        return self._room("discover_rooms", service)

    def join_room(self, room, nick, password=""):
        return self._room("join_room", room, nick, password)

    def create_room(self, room, nick):
        return self._room("create_room", room, nick)

    def leave_room(self, room, nick):
        return self._room("leave_room", room, nick)

    def destroy_room(self, room, reason=""):
        return self._room("destroy_room", room, reason)

    def room_standing(self, room, nick):
        return self._room("room_standing", room, nick)

    def joined_rooms(self):
        return self._room("joined_rooms")


def build(*, answer=None, raises=None, connect=True):
    made = {}

    def factory(p, password, **kw):
        made["transport"] = FakeTransport(p, password, answer=answer,
                                          raises=raises, **kw)
        return made["transport"]

    app = FakeApp()
    ctl = ConnectionController(
        app, ConnectionProfile(jid=JID, server=SERVER),
        transport_factory=factory,
        prober=lambda _p, **_kw: SamProbe(True, "ok", "fine", "3.1"))
    if connect:
        ctl.connect("pw")
    made["app"] = app
    return ctl, made


# ── one shape ────────────────────────────────────────────────────────────────

OPERATIONS = [
    ("discover_services", ()),
    ("discover_rooms", (MUC_SERVICE,)),
    ("join_room", (ROOM, NICK)),
    ("create_room", (ROOM, NICK)),
    ("leave_room", (ROOM, NICK)),
    ("destroy_room", (ROOM,)),
    ("room_standing", (ROOM, NICK)),
    ("joined_rooms", ()),
]


class TestEveryOperationAnswersTheSameWay:

    @pytest.mark.parametrize("name,args", OPERATIONS)
    def test_it_returns_the_four_fields(self, name, args):
        ctl, _ = build()
        got = getattr(ctl, name)(*args)
        assert set(got) == {"ok", "code", "detail", "value"}

    @pytest.mark.parametrize("name,args", OPERATIONS)
    def test_it_never_raises_when_the_transport_does(self, name, args):
        ctl, _ = build(raises=RuntimeError("boom"))
        got = getattr(ctl, name)(*args)
        assert got["ok"] is False
        assert got["code"] in muc.CODES

    @pytest.mark.parametrize("name,args", OPERATIONS)
    def test_it_answers_before_there_is_a_connection(self, name, args):
        ctl, _ = build(connect=False)
        got = getattr(ctl, name)(*args)
        assert got["ok"] is False
        assert got["code"] == "network"
        assert "Connect" in got["detail"]

    @pytest.mark.parametrize("name,args", OPERATIONS)
    def test_a_refusal_carries_the_services_code(self, name, args):
        ctl, _ = build(answer=("forbidden", muc.CODES["forbidden"], None))
        got = getattr(ctl, name)(*args)
        assert got["ok"] is False
        assert got["code"] == "forbidden"
        assert got["detail"] == muc.CODES["forbidden"]


class TestWhatReachesTheTransport:

    def test_join_passes_the_room_the_nickname_and_the_password(self):
        ctl, made = build()
        ctl.join_room(ROOM, NICK, "hunter2")
        assert made["transport"].calls[-1] == \
            ("join_room", ROOM, NICK, "hunter2")

    def test_destroy_passes_the_reason(self):
        ctl, made = build()
        ctl.destroy_room(ROOM, "moved")
        assert made["transport"].calls[-1] == ("destroy_room", ROOM, "moved")

    def test_discovery_passes_the_service(self):
        ctl, made = build()
        ctl.discover_rooms(MUC_SERVICE)
        assert made["transport"].calls[-1] == \
            ("discover_rooms", MUC_SERVICE)

    def test_the_value_comes_back_untouched(self):
        rooms = [{"jid": ROOM, "name": "General"}]
        ctl, _ = build(answer=("ok", muc.CODES["ok"], rooms))
        assert ctl.discover_rooms(MUC_SERVICE)["value"] == rooms


# ── the local gate ───────────────────────────────────────────────────────────

class TestRefusedBeforeARoundTripIsSpent:
    """Over three I2P hops a wasted round trip is tens of seconds."""

    def test_a_room_address_with_a_nickname_is_refused_here(self):
        ctl, made = build()
        got = ctl.join_room(ROOM + "/bob", NICK)
        assert got["ok"] is False
        assert got["code"] == "bad_request"
        assert made["transport"].calls == []

    def test_an_address_that_is_not_one_is_refused_here(self):
        ctl, made = build()
        assert ctl.join_room("general", NICK)["ok"] is False
        assert made["transport"].calls == []

    def test_an_empty_nickname_is_refused_here(self):
        ctl, made = build()
        assert ctl.join_room(ROOM, "  ")["ok"] is False
        assert made["transport"].calls == []

    def test_creating_is_gated_the_same_way(self):
        ctl, made = build()
        assert ctl.create_room("nonsense", NICK)["ok"] is False
        assert made["transport"].calls == []

    def test_a_valid_request_is_not_gated(self):
        ctl, made = build()
        assert ctl.join_room(ROOM, NICK)["ok"] is True
        assert made["transport"].calls != []

    def test_leaving_is_not_gated(self):
        """A room you are IN is one the service already accepted the address
        of. Refusing to leave it because our own validator dislikes the name
        would strand somebody in a room."""
        ctl, made = build()
        ctl.leave_room("odd name@" + MUC_SERVICE, NICK)
        assert made["transport"].calls != []


# ── the trace ────────────────────────────────────────────────────────────────

class TestItRecordsWhatWasDoneNotWhereOrByWhom:
    """§7. A room address says who somebody talks to in a group, which is
    more identifying than a single JID rather than less."""

    def test_the_operation_and_its_code_are_recorded(self):
        ctl, _ = build(answer=("conflict", muc.CODES["conflict"], None))
        ctl.join_room(ROOM, NICK)
        text = ctl.diagnostic_report()
        assert "join_room" in text
        assert "conflict" in text

    def test_the_room_is_not(self):
        ctl, _ = build()
        ctl.join_room(ROOM, NICK)
        ctl.discover_rooms(MUC_SERVICE)
        text = ctl.diagnostic_report()
        assert "general" not in text
        assert "rooms.xmpp-elite" not in text

    def test_the_nickname_is_not(self):
        ctl, _ = build()
        ctl.join_room(ROOM, "verydistinctivenick")
        assert "verydistinctivenick" not in ctl.diagnostic_report()

    def test_a_room_password_is_not(self):
        ctl, _ = build()
        ctl.join_room(ROOM, NICK, "correct-horse-battery")
        assert "correct-horse-battery" not in ctl.diagnostic_report()


# ── the fake cannot agree with a mistake ─────────────────────────────────────

class TestTheFakeMatchesTheRealTransport:

    @pytest.mark.parametrize("name", [name for name, _ in OPERATIONS])
    def test_the_real_transport_has_it(self, name):
        from android_bridge.transport import XmppTransport

        assert hasattr(XmppTransport, name), name

    @pytest.mark.parametrize("name", [name for name, _ in OPERATIONS])
    def test_the_signatures_match(self, name):
        import inspect

        from android_bridge.transport import XmppTransport

        real = inspect.signature(getattr(XmppTransport, name)).parameters
        mine = inspect.signature(getattr(FakeTransport, name)).parameters
        assert list(real) == list(mine), name
