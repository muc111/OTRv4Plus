# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Password-protected rooms: created with one, entered with one.

Creating: the XEP-0045 room-configuration form sets
`muc#roomconfig_passwordprotectedroom` and `muc#roomconfig_roomsecret`, and
the room's disco#info is read back. A service that did not apply it would
leave an OPEN room the user believes is closed -- that room is destroyed and
the create fails.

Entering: the password goes into the join presence (`join_muc_wait(...,
password=)`); a room that wants one refuses with not-authorized, which is
the code the app's prompt opens on.
"""

import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import otrv4plus_muc as muc_rules
from tests.test_android_rooms import (FakeDisco, FakeMuc, PresenceError,
                                      build, ROOM, NICK)

slixmpp = pytest.importorskip("slixmpp")

SECRET = "correct horse battery staple"


def real_forms(client):
    real = slixmpp.ClientXMPP("a@b.i2p", "pw")
    real.register_plugin("xep_0004")
    client.plugins["xep_0004"] = real.plugin["xep_0004"]


def protected_disco(applied=True):
    features = ["http://jabber.org/protocol/muc"]
    if applied:
        features.append("muc_passwordprotected")
    return FakeDisco(info={ROOM: ([("conference", "text", None, "")],
                                  features)})


def create(applied=True, password=SECRET):
    room = FakeMuc()
    t, made = build(disco=protected_disco(applied), muc=room)
    real_forms(made["client"])
    try:
        result = t.create_room(ROOM, NICK, password)
    finally:
        t.close()
    return result, room


class TestCreatingAPasswordProtectedRoom:

    def test_the_form_sets_protection_and_the_secret(self):
        (code, _d, _v), room = create()
        assert code == "ok"
        form = room.configured[0][1]
        fields = form.get_fields()
        assert fields["muc#roomconfig_passwordprotectedroom"]["value"] is True
        assert fields["muc#roomconfig_roomsecret"]["value"] == SECRET
        assert "http://jabber.org/protocol/muc#roomconfig" in str(form)
        assert room.destroyed == []

    def test_a_service_that_did_not_protect_it_gets_it_removed(self):
        (code, detail, value), room = create(applied=False)
        assert code == "password_not_applied"
        assert value is None
        assert room.destroyed and room.destroyed[0][0] == ROOM, (
            "an OPEN room was left behind that the user believes is closed")
        assert "removed" in detail

    def test_without_a_password_the_form_is_still_empty(self):
        room = FakeMuc()
        t, made = build(muc=room)
        real_forms(made["client"])
        try:
            assert t.create_room(ROOM, NICK)[0] == "ok"
        finally:
            t.close()
        assert room.configured[0][1].get_fields() == {}


class TestEnteringAPasswordProtectedRoom:

    def test_the_password_goes_into_the_join(self):
        room = FakeMuc()
        t, _ = build(muc=room)
        try:
            assert t.join_room(ROOM, NICK, SECRET)[0] == "ok"
        finally:
            t.close()
        assert room.joined == [(ROOM, NICK, SECRET)]

    def test_a_room_wanting_a_password_is_not_authorized(self):
        """The code the app's password prompt opens on."""
        t, _ = build(muc=FakeMuc(join_fails=PresenceError("not-authorized")))
        try:
            code, detail, _v = t.join_room(ROOM, NICK)
        finally:
            t.close()
        assert code == "not_authorized"
        assert "password" in detail


class TestTheController:

    def _controller(self, calls):
        from android_bridge.connection import ConnectionController

        class T:
            def create_room(self, *a):
                calls.append(a)
                return ("ok", "Done.", {})

        c = ConnectionController.__new__(ConnectionController)
        c._transport = T()
        c._noting_room = lambda result, room, joined: result
        return c

    def test_a_password_is_passed_through(self):
        calls = []
        self._controller(calls).create_room(ROOM, NICK, SECRET)
        assert calls == [(ROOM, NICK, SECRET)]

    def test_no_password_keeps_the_old_call(self):
        calls = []
        self._controller(calls).create_room(ROOM, NICK)
        assert calls == [(ROOM, NICK)]

    def test_a_bad_password_is_refused_before_anything_is_sent(self):
        calls = []
        c = self._controller(calls)
        for bad in ("   ", "x" * 129, "a\x00b"):
            assert c.create_room(ROOM, NICK, bad)["ok"] is False
        assert calls == []

    def test_the_password_never_reaches_the_trace(self):
        from android_bridge.trace import TRACE
        calls = []
        self._controller(calls).create_room(ROOM, NICK, SECRET)
        assert SECRET not in str(TRACE.render() if hasattr(TRACE, "render")
                                 else TRACE.__dict__)


def test_validation_matches_kotlin():
    assert muc_rules.validate_room_password(SECRET) is None
    assert muc_rules.validate_room_password("") is not None
    assert muc_rules.MAX_ROOM_PASSWORD == 128


class TestTheScreen:
    """Compose compiles only in CI; the wiring is read from source."""

    @pytest.fixture(scope="class")
    def screen(self):
        with open(os.path.join(ROOT, "android/app/src/main/java/org/otrv4plus/"
                               "android/ui/RoomsScreen.kt"), encoding="utf-8") as fh:
            return fh.read()

    def test_create_offers_a_password_option(self, screen):
        assert "Password protect a new room" in screen
        assert "model.create(address.trim(), nick.trim()," in screen

    def test_passwords_are_masked_and_never_saved_to_the_bundle(self, screen):
        assert screen.count("PasswordVisualTransformation()") >= 2
        assert 'var roomPassword by remember { mutableStateOf("") }' in screen
        assert "rememberSaveable { mutableStateOf(\"\") }\n        var roomPassword" \
            not in screen
        assert not any("rememberSaveable" in line and "assword" in line
                       for line in screen.splitlines())

    def test_a_refused_join_opens_the_prompt_and_enter_retries(self, screen):
        assert "model.passwordPrompt?.let" in screen
        assert "model.submitPassword(entered)" in screen
        assert "RoomPassword.NOT_ENCRYPTION" in screen
